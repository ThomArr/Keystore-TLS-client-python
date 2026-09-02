from app.graphics.tinker import AppWindow
from app.sharepoint.cloud_handler import SharePointCloudHandler
from app.azure.key_provider import AzureKEKProvider


def main():
    path = "config/sharepoint.credentials"
    key_provider = AzureKEKProvider()

    cloud = SharePointCloudHandler(key_provider, path)

    win = AppWindow(cloud)
    win.run()


main()