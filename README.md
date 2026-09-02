## How to get started

### Prerequisites
#### Environment
A Linux environment supporting at least Python version 3.13 (e.g. Debian Trixie).  

Clone the repo :
> git clone https://github.com/anaelmessan/Keystore-TLS-client-python.git  

#### HSM
Encryption keys need to be set on the HSM :
> t<keyslot (1 byte, hex)><key (16 bytes, hex)>

### Configuration
Warning : Limit the permission of those files and please ensure you never upload them on github.
#### Azure
The connection string should be put in cofig/azure.credentials.  
[Azurite](https://hub.docker.com/r/microsoft/azure-storage-azurite) can instead be used to emulate Azure Blob storage. If you prefer doing that, you can follow the instructions below.  
It can be installed using docker or podman. When no azure.credentials file is found, the connection string used defaults to Azurite's one.  
An argument might need to be added to the container when Azurite is out of date.  
>--skipApiVersionCheck  

IMPORTANT : The keystores to use have to be configured in app/azure/key_provider.py.  

#### Amazon
config/amazon_s3/credentials:
>[default]  
>aws_access_key_id =   
>aws_secret_access_key = 

#### Python version
Python version can be set in the Makefile. Change the PYTHON3_BINARY variable.  
If necessary, delete .venv and run:
> make install_deps


### Running
Install dependencies:
> make install_deps  

If there is an error, ensure that Python venv is installed (_python3-venv_ package on Debian).  

Run the Azure client:  
> make run_azure

Run the Amazon client:  
> make run_amazon

Run the Google client:  
> make run_google

Run the intermediate Amazon server:  
> make run_intermediate_server


A `config.yaml` file is needed (private).


### TODO
- Docker
- AWS
- Use the implementation of multiple requests in the code.
- Add more logging
- Select keystores to connect to
- Set keys easily
- Timeout for azure 

### Notes
When using the same local connection (same socket) to send different requests to different keystores, wait for the response of the last request sent or use a connection per keystore. The ordering of the responses received is guaranteed only on the same keystore when the requests originate from the same socket.

### Native TLS Wrapper

The HSM TLS connection relies on a small native C shared library: core/tls/libhsm_tls.so

Unlike the rest of the project, which is written in Python, this component is implemented in C and uses OpenSSL directly to configure TLS 1.3 PSK communication and the required ciphersuite: TLS_AES_128_CCM_SHA256

The shared library is built automatically when running:

> make run_azure  
> make run_amazon  
> make run_google

It can also be rebuilt manually with:

> make build_hsm_tls