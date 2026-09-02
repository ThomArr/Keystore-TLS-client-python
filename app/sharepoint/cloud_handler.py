import os
import json
import base64
import requests
import msal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


GRAPH = "https://graph.microsoft.com/v1.0"


class SharePointCloudHandler:
    """
    Class to handle requests to SharePoint.
    """

    def __init__(self, key_provider, credentials_path=None):
        self.__service_name = "SharePoint"
        self.key_provider = key_provider
        self.credentials_path = credentials_path

        self.connected = False
        self.token = None
        self.site_id = None
        self.drive_id = None
    
    def get_list_containers(self) -> list[str]:
        data = self.__get(f"{GRAPH}/drives/{self.drive_id}/root/children").json()

        folders = [
            item["name"]
            for item in data.get("value", [])
            if "folder" in item
        ]

        return ["Documents"] + folders
    
    def get_list_files(self, container_name: str) -> list[str]:
        folder = self.__folder_path(container_name)

        if folder:
            url = f"{GRAPH}/drives/{self.drive_id}/root:/{folder}:/children"
        else:
            url = f"{GRAPH}/drives/{self.drive_id}/root/children"

        data = self.__get(url).json()

        files = []
        for item in data.get("value", []):
            name = item["name"]
            if "file" in item and not name.endswith(".metadata.json"):
                files.append(name)

        return files
    
    def connect_hsm(self):
        self.key_provider.connect()

    def connect_cloud(self):
        cfg = self.__read_credentials()

        app = msal.ConfidentialClientApplication(
            cfg["client_id"],
            authority=f"https://login.microsoftonline.com/{cfg['tenant_id']}",
            client_credential=cfg["client_secret"],
        )

        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        
        if "access_token" not in result:
            raise RuntimeError(result)

        self.token = result["access_token"]

        self.site_id = self.__get_site_id(
            cfg["sharepoint_hostname"],
            cfg["sharepoint_site_path"],
        )

        self.drive_id = self.__get_drive_id()

        self.connected = True
        print("Connected to the cloud.")

    def upload(self, path: str, container_name: str, filename: str):
        full_key = b"2.0\00\00\00\00\00" + os.urandom(32)
        raw_key = full_key[8:]

        wrapped_key = self.key_provider.wrap_key(full_key)

        nonce = os.urandom(12)

        with open(path, "rb") as stream:
            plaintext = stream.read()

        aesgcm = AESGCM(raw_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        target = self.__target_path(container_name, filename)
        metadata_target = self.__target_path(
            container_name,
            filename + ".metadata.json",
        )

        self.__put_content(target, ciphertext)

        metadata = {
            "algorithm": "AESGCM",
            "key_wrap_algorithm": self.key_provider.get_key_wrap_algorithm(),
            "kid": self.key_provider.get_kid(),
            "nonce": base64.b64encode(nonce).decode(),
            "wrapped_key": base64.b64encode(wrapped_key).decode(),
        }

        self.__put_content(
            metadata_target,
            json.dumps(metadata).encode(),
        )

    def download(self, path: str, container_name: str, filename: str):
        target = self.__target_path(container_name, filename)
        metadata_target = self.__target_path(
            container_name,
            filename + ".metadata.json",
        )

        ciphertext = self.__get_content(target)

        metadata = json.loads(
            self.__get_content(metadata_target).decode()
        )

        nonce = base64.b64decode(metadata["nonce"])
        wrapped_key = base64.b64decode(metadata["wrapped_key"])

        full_key = self.key_provider.unwrap_key(
            wrapped_key,
            metadata["key_wrap_algorithm"],
        )

        raw_key = full_key[8:]

        aesgcm = AESGCM(raw_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(path, "wb") as file:
            file.write(plaintext)

    def create_container(self, container_name: str):
        if container_name == "Documents":
            return

        body = {
            "name": container_name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "fail",
        }

        try:
            self.__post(
                f"{GRAPH}/drives/{self.drive_id}/root/children",
                json=body,
            )
        except requests.HTTPError as error:
            if error.response.status_code == 409:
                print("A container with this name already exists.")
            else:
                raise

    def get_service_name(self):
        return self.__service_name
    
    def __get_site_id(self, hostname: str, site_path: str) -> str:
        url = f"{GRAPH}/sites/{hostname}:/{site_path}:"
        return self.__get(url).json()["id"]

    def __get_drive_id(self) -> str:
        url = f"{GRAPH}/sites/{self.site_id}/drive"
        return self.__get(url).json()["id"]

    def __folder_path(self, container_name: str) -> str:
        if not container_name or container_name == "Documents":
            return ""
        return container_name

    def __target_path(self, container_name: str, filename: str) -> str:
        folder = self.__folder_path(container_name)

        if folder:
            return f"{folder}/{filename}"

        return filename

    def __put_content(self, target: str, data: bytes):
        url = f"{GRAPH}/drives/{self.drive_id}/root:/{target}:/content"
        self.__put(url, data=data)

    def __get_content(self, target: str) -> bytes:
        url = f"{GRAPH}/drives/{self.drive_id}/root:/{target}:/content"
        return self.__get(url).content

    def __headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def __get(self, url):
        response = requests.get(url, headers=self.__headers())
        response.raise_for_status()
        return response

    def __post(self, url, **kwargs):
        response = requests.post(url, headers=self.__headers(), **kwargs)
        response.raise_for_status()
        return response

    def __put(self, url, **kwargs):
        response = requests.put(url, headers=self.__headers(), **kwargs)
        response.raise_for_status()
        return response

    def __read_credentials(self):
        cfg = {}

        with open(self.credentials_path, "r") as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                key, value = line.split("=", 1)
                cfg[key.strip()] = value.strip()

        return cfg