# audit log
Receive audit records on a TCP socket, store the received data, and response with +OK or -ERROR.

The data is stored in a simple file, framed by prefixing the records with length in ASCII.
See [auditlog](./auditlog/README.md)

