For information about work before repository switch, see commits in the old repository [here](https://github.com/clubnix/nginx-rp-manager/commits/master).

## Introduction

This is a simple web application that allows you to manage your Nginx reverse proxy configuration. It is written in Python using the Flask web framework.

## Features

- Add, edit, and delete reverse proxy configurations
- View the current Nginx configuration
- Automatically reload Nginx after changes are made
- Automatically validate Nginx configuration before reloading

## Installation

Create a docker compose file with the following content:

```yaml
services:
  reverse-proxy:
    container_name: reverse-proxy
    build:
      context: ./reverse-proxy
      dockerfile: Dockerfile
    ports:
      - 80:80
      - 443:443
    volumes:
      - logs:/var/log/nginx
      - conf:/etc/nginx/conf.d
      - certs:/etc/nginx/certs
      - scripts:/opt/scripts
    restart: unless-stopped

  web-manager:
    container_name: web-manager
    build:
      context: ./web-manager
      dockerfile: Dockerfile
    environment:
      - SSL_COUNTRY=FR
      - SSL_STATE=France
      - SSL_CITY=Noisy-le-Grand
      - SSL_ORGANIZATION_GLOBAL=ESIEE Paris
      - SSL_ORGANIZATION_UNIT=Club*Nix
      - SSL_DAYS=365
    ports:
      - 5000:5000
    volumes:
      - logs:/app/nginx/logs
      - conf:/app/nginx/conf.d
      - certs:/app/nginx/certs
      - scripts:/app/scripts
      - ./logs:/app/logs
    restart: unless-stopped

volumes:
  logs:
  conf:
  certs:
  scripts:
```

You can then run the following command to start the services:

```bash
docker compose up -d
```

The web manager will be available at [http://localhost:5000](http://localhost:5000).

## Configuration

The web manager uses environment variables to configure the SSL certificate generation. The following variables are available:

- `SSL_COUNTRY`: The country code for the SSL certificate (default: `FR`)
- `SSL_STATE`: The state for the SSL certificate (default: `France`)
- `SSL_CITY`: The city for the SSL certificate (default: `Noisy-le-Grand`)
- `SSL_ORGANIZATION_GLOBAL`: The global organization for the SSL certificate (default: `ESIEE Paris`)
- `SSL_ORGANIZATION_UNIT`: The organization unit for the SSL certificate (default: `Club*Nix`)
- `SSL_DAYS`: The number of days the SSL certificate is valid for (default: `365`)

### Volumes

There are four volumes that are used by the services:

- `logs`: The Nginx logs directory
- `conf`: The Nginx configuration directory
- `certs`: The Nginx certificates directory
- `scripts`: The scripts directory

The `logs`, `conf`, and `certs` volumes are shared between the reverse proxy and the web manager.

The `scripts` volume is used to communicate and execute reload and validation scripts between the services.

The `./logs` volume is used to store the web manager logs.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

