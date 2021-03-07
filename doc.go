// Copyright (C) 2021 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package akcss

const usage = `Akcss - OpenVPN Manager
iDigitalFlame 2021 (idigitalflame.com)

General
  -c                              Configuration file path, defaults
                                   to "akcss.conf" or "${AKCSS_CONF}".
  -r                              Send a reload signal to the daemon.
  --daemon                        Start in daemon mode.

Server Commands
  --list                          Get a list of all servers.
  --stop          <ID>            Stop a server with the specified ID.
  --start         <ID>            Start a server with the specified ID.
                                   Also valid included in (--new) and will
                                   start the server once created.
  --renew         <ID>            Renews a specified server certificate.
  --status        <ID>            Get status of server with the specified ID.
  --restart       <ID>            Restart a server with the specified ID.
                                   Also valid included in (--edit) and will
                                   restart the server once changes are complete.
  --crl           [ID]            Instruct the server to generate it's
                                   CRL file. If empty, this will instruct
                                   all servers to generate their CRL instead.

Server Actions
  --new           <ID> [hostname] New server with ID and optional hostname.
  --edit          <ID>            Edit the sever options by server ID.
  --list          <ID>            Get a list of valid VPN certificates for
                                   the server ID.
  --delete        <ID>            Delete a Server by the specified ID.
  --print         <ID>            Print server details by the specified ID.

Server Options (for --new and --edit)
  --hostname      <hostname>      The DNS address clients will connect to.
  --port          <1-65535: 443>  The port number to listen on.
  --proto         <[tcp]|udp>     The protocol to listen on either tcp or udp.
  --auto                          Start the server when the daemon starts.
  --limit         <1-65535: 64>   The max amount of clients that can connect.
  --timeout       <1-65535: 120>  The timeout for the server connections.
  --interval      <1-65535: 10>   The interval for keepalive pings.
  --days          <1-65536: 365>  Days the server certificate is valid for.
                                   Defaults to 365 days (1 year). Also changes the
                                   default server renew period time.
  --server-days   <1-65536: 365>  Alias of the "--days" option.
  --client-days   <1-65536: 365>  Default days that a client certificate is valid
                                   for. Can be overridden by "--days" when creating
                                   a new client. Behaves differently when creating
                                   a new client certificate.
  --over-client   <file path>     Path of a file that includes an override file
                                   that specifies additional client configuration
                                   options. File is similar to an OpenVPN profile
                                   but ignores comments and will negate/remove
                                   generated options on lines starting with "!".
                                   Can be empty to unset, but paths must be valid
                                   during server runtime.
  --over-server   <file path>     Path of a file that includes an override file
                                   that specifies additional server configuration
                                   options. File is similar to an OpenVPN profile
                                   but ignores comments and will negate/remove
                                   generated options on lines starting with "!".
                                   Can be empty to unset, but paths must be valid
                                   during server runtime.

  VPN Network Options
    --crosstalk                   Clients are allowed to connect to eachother.
    --net         <network>       The network that clients will use.
    --net-start   <IP>            The starting address for leases.
    --net-end     <IP>            The end address for leases.
    --net-mask    <network mask>  The network mask for '-net'.

  CA Options (only valid for --new)
    --ca          <ca name>       Name of the CA certificate.
    --ca-days     <1-65536: 3650> Days the CA certificate is valid for.
                                   Defaults to 3650 days (10 years).

  Certificate Subject Options
    --org         <organization>  Server certificate organization name.
    --dept        <department>    Server certificate department name.
    --street      <street>        Server certificate street address.
    --city        <city>          Server certificate city name.
    --state       <state>         Server certificate state or providence.
    --country     <country code>  Server certificate 2-letter country code.
    --domain      <domain>        Server certificate domain to append.
    --email       <email>         Server certificate administrative email.

  DH Options
    --dh-path     <file path>     Use the supplied file path for DHParams
                                   File is only read by the VPN process
                                   and must be readable by root/nobody.
                                   Path is not verified and can be empty to
                                   Unset the previous path. Takes priority
                                   over stored DHParams data.
    --dh-file     <file path>     Read and use the provided file for
                                   DHParams. This will fail if the file
                                   does not exist. Overrites the previous
                                   DHParam data saved.
    --dh-size     <0|2048|[4096]> Size of the initial DHparam file.
                                   Can be 2048 or 4096, defaults to 4096.
                                   Size of 0 can omit DHparam generation.
    --no-dh                       Remove DHParams file and data. Similar to
                                   (--dh-path "" --dh-size 0).

  TLS Secrets Options
    --tls-path     <file path>    Use the supplied file path for TLS secrets
                                   File is only read by the VPN process
                                   and must be readable by root/nobody.
                                   Path is not verified and can be empty to
                                   Unset the previous path. Takes priority
                                   over stored DHParams data.
    --tls-file     <file path>    Re-generate TLS secrets if not already generated.
    --tls-gen                     Re-generate TLS secrets if not already generated.
                                   This will regenerate DHParams data if size is
                                   greater than zero and a DHParams path is not
                                   empty. Generation occurs in the background.
    --tls-reset                   Re-generate secrets even if already generated.
                                   WARNING! This will invalidate any currently
                                   generated OVPN connection profiles. This will
                                   regenerate TLS secrets data and remove any set
                                   paths or files.
    --force                       Do not ask for confirmation before resetting.

Server Options (for --delete)
  --soft                          Leave files when removing.
  --force                         Do not ask for confirmation before removing.

OpenVPN Option Actions
  --opt           <ID>            List the options configured for the server.
  --del-opt       <ID> <option>   Delete an option by it's value.
  --new-opt       <ID> <option>   Add a new option to the server.

  Additional Options (for --new-opt)
    --push                        Set the option to be pushed by the server.
    --push-client                 Set the option to be pushed in connection files.

OpenVPN Client Option Actions
  --cc           <ID>             List the client options on the server.
  --del-cc       <ID> <name> <V>  Delete the client config by client name and value.
  --new-cc       <ID> <name> <V>  Add a new client config to the supplied client.

Client Actions
  --del-client    <ID> <name>     Remove and revoke a client.
  --new-client    <ID> <name>     Add a new client to the server.

  Additional Options (for --del-client)
    --force                       Do not ask for confirmation before deleting.

  Additional Options (for --new-client)
    --days        <1-65536: 365> Days the new client certificate is valid for.
                                   Defaults to 365 days (1 year).
    --client-days <1-65536: 365> Alias of "--days" when creating a new client.
    --file        <file>          Output the client profile to the supplied file.
                                   Defaults to standard output.

Notification Actions
  --notify        <ID>            List notifiers for the server.
  --del-notify    <ID> <email>    Delete notification entries for this address.
  --new-notify    <ID> <email>    Subscribe the email to notification entries.
                                   This will default to ALL. Specify specific types
                                   using the "--actions" argument.

  Additional Options (for --new-notify)
    --actions     <A,A,N...>      Specify notification types to trigger on.
                                   Can be any of the following (comma seperated).
                                   "crl,stop,start,renew,create,expire,revoke
                                   connect,disconnect".
`
