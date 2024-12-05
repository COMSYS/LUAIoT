# Code to our framework LUA-IoT: Let's Usably Authenticate the IoT

This repository contains the implementation of the LUA-IoT framework, which is designed to authenticate IoT devices that do not possess globally verifiable identifiers. The framework consists of a Certificate Authority (CA) and client components to manage the certification of IoT devices.

If you use any portion of our work, please cite our paper:

```bibtex
@inproceedings{2024_dahlmanns_lua-iot,
  author    = {Dahlmanns, Markus and Pennekamp, Jan and Decker, Robin and Wehrle, Klaus},
  title     = {{LUA-IoT: Let's Usably Authenticate the IoT}},
  booktitle = {Proceedings of the 27th Annual International Conference on Information Security and Cryptology (ICISC '24), November 20-22, 2024, Seoul, Korea},
  year      = {2024},
  publisher = {Springer}
}
```

_Note that we used Github Copilot to improve the code's readability and document our code for publication._

## Certificate Authority (CA)

The CA component is responsible for managing the registration, certification, and revocation of IoT devices. It includes scripts for creating and revoking end device entries and a server to handle incoming requests from clients.

### Running the CA

To run the CA server, navigate to the `CA/server` directory and execute the following command:

```sh
cd CA/server
python3 server.py
```

### Registering an End Device
To register an end device at the CA, run the following command from the main directory:

```sh
python3 CA/scripts/create_end_device_entry.py --identifier <device_identifier> --publicKey <public_key_file> --user <username> --email <email> --telephone <phone_number> --country <country> --state <state> --city <city>
```

### Revoking an End Device
To revoke an end device, run the following command from the main directory:

```sh
python3 CA/scripts/revoke_end_device.py --identifier <device_identifier> --revocationReason <reason>
```

## Client

The client component includes the necessary headers and source files to handle the authentication process, including creating and managing authentication structures, sending and receiving messages, and handling certification.

### Client Files

* `authentication_scheme_codes.h`: Defines return codes for the authentication scheme.
* `authentication_struct.h`: Defines the structure and related functions for managing authentication.
* `certification.c` and `certification.h`: Handle the certification process of end devices.
* `identifier.c` and `identifier.h`: Manage device identifiers.
* `request_message.c` and `request_message.h`: Handle the creation and parsing of request messages.
* `response_message.c` and `response_message.h`: Handle the creation and parsing of response messages.
* `trust_properties.h`: Defines properties related to trust and security.

## Dependencies

Our code requires dependencies to run.

### CA

The CA server uses Python and the Python binding of GnuTLS for TLS communication.

### Client

The client code provides a library but needs the actual implementation to handle the (D)TLS connection to the CA.
