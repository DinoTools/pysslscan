import datetime

from sslscan import modules, _helper as helper
from sslscan.module.report import BaseReport


class Terminal(BaseReport):
    """
    Print results to the terminal.
    """

    name = "term"

    def __init__(self, **kwargs):
        BaseReport.__init__(self, **kwargs)
        self._rating = None
        self.color = helper.ColorConsole()

    def _print_client_ciphers(self, kb):
        ciphers = kb.get("client.ciphers")
        if ciphers is None:
            return

        print("Supported Client Cipher(s):")
        for cipher in ciphers:
            rating_bits = self._rating.rate('cipher.bits', cipher)
            rating_method = self._rating.rate('cipher.method', cipher)
            rating_name = self._rating.rate('cipher.name', cipher)
            print(
                "  {3}{0:7}{6} {4}{1:>9}{6} {5}{2}{6}".format(
                    cipher.method_name,
                    "%d bits" % cipher.bits,
                    cipher.name,
                    helper.rating2color(self.color, rating_method),
                    helper.rating2color(self.color, rating_bits),
                    helper.rating2color(self.color, rating_name),
                    self.color.RESET
                )
            )
        print("")

    def _print_custom(self, kb, base_id):
        kb_ids = kb.get_group_ids(base_id)
        if len(kb_ids) == 0:
            return

        for kb_id in kb_ids:
            item = kb.get(kb_id)
            print(item.label)

            sub_items = kb.get_list(kb_id)
            sub_ids = list(sub_items.keys())
            sub_ids.sort()
            for sub_id in sub_ids:
                sub_item = sub_items.get(sub_id)
                tmp_value = sub_item.value

                tmp_rating = self._rating.rate(sub_id, tmp_value)

                if isinstance(tmp_value, bool):
                    tmp_value = "yes" if tmp_value else "no"

                print(
                    "  {0}: {2}{1}{3}".format(
                        sub_item.label,
                        tmp_value,
                        helper.rating2color(self.color, tmp_rating),
                        self.color.RESET
                    )
                )
            print("")

    def _print_server_certificate(self, kb):
        x509 = kb.get("server.certificate")
        if x509 is None:
            return

        x509name_members = [
            "countryName",
            "stateOrProvinceName",
            "localityName",
            "organizationName",
            "organizationalUnitName",
            "commonName",
            "emailAddress"
        ]
        print("SSL Certificate:")
#        print("    Certificate blob:")
#        print(x509.get_certificate_blob())
        print("  Version: %lu" % x509.get_version())
        tmp = x509.get_serial_number()
        print("  Serial Number: %lu (0x%lx)" % (tmp, tmp))
        print("  Signature Algorithm: %s" % x509.get_signature_algorithm().decode("ASCII"))
        tmp_issuer = x509.get_issuer()
        if tmp_issuer:
            print("  Issuer:")
            for tmp_name in x509name_members:
                tmp_value = getattr(tmp_issuer, tmp_name)
                if tmp_value is None:
                    tmp_value = ""
                print("    {}: {}".format(
                    tmp_name,
                    tmp_value
                ))
        tmp_date = datetime.datetime.strptime(
            x509.get_notBefore().decode("ASCII"),
            "%Y%m%d%H%M%SZ"
        )
        print("  Not valid before: %s" % str(tmp_date))
        tmp_date = datetime.datetime.strptime(
            x509.get_notAfter().decode("ASCII"),
            "%Y%m%d%H%M%SZ"
        )
        print("  Not valid after: %s" % str(tmp_date))
        tmp_subject = x509.get_subject()
        if tmp_subject:
            print("  Subject:")
            for tmp_name in x509name_members:
                tmp_value = getattr(tmp_subject, tmp_name)
                if tmp_value is None:
                    tmp_value = ""
                print("      {}: {}".format(
                    tmp_name,
                    tmp_value
                ))
#        pk = x509.get_pubkey()
#        if pk:
#            print("    Public Key Algorithm: %s" % pk.get_algorithm())
#            tmp_name = pk.get_type_name()
#            if tmp_name:
#                tmp_bits = pk.get_bits()
#                if tmp_bits:
#                    print("    %s Public Key: (%d bit)" % (tmp_name, tmp_bits))
#                else:
#                    print("    %s Public Key:" % tmp_name)
#                print(pk.get_key_print(6))
#            else:
#                print("    Public Key: Unknown")
#        else:
#            print("   Public Key: Could not load")
#
        tmp_ext_count = x509.get_extension_count()
        print("  X509v3 Extensions({}):".format(tmp_ext_count))
        for i in range(tmp_ext_count):
            extension = x509.get_extension(i)
            tmp_short_name = extension.get_short_name()
            tmp_short_name = tmp_short_name.decode("ASCII")
            print(
                "    {}: {}".format(
                    tmp_short_name,
                    "critical" if extension.get_critical() else ""
                )
            )
            # ToDo: format byte string
            print(extension.get_data())
#
#        print("  Verify Certificate:")
#        verfy_status = host.get("certificate.verify.status", None)
#        if verfy_status:
#            print("    Certificate passed verification")
#        else:
#            print("    %s" % host.get("certificate.verify.error_message", ""))
        print("")

    def _print_server_ciphers(self, kb):
        ciphers = kb.get("server.ciphers")
        if ciphers is None:
            return

        print("Supported Server Cipher(s):")
        for cipher in ciphers:
            rating_bits = self._rating.rate('cipher.bits', cipher)
            rating_method = self._rating.rate('cipher.method', cipher)
            rating_name = self._rating.rate('cipher.name', cipher)
            print(
                "  {0:9} {5}{1:7}{8} {6}{2:>9}{8} {7}{3}{8}  {4}".format(
                    cipher.status_name.capitalize(),
                    cipher.method_name,
                    "%d bits" % cipher.bits,
                    cipher.name,
                    "", # reserved for alert info
                    helper.rating2color(self.color, rating_method),
                    helper.rating2color(self.color, rating_bits),
                    helper.rating2color(self.color, rating_name),
                    self.color.RESET
                )
            )
        print("")

    def _print_host_renegotiation(self, kb):
        if kb.get("server.renegotiation.support") is None:
            return

        reneg_support = kb.get("server.renegotiation.support")
        rating_renegotiation = self._rating.rate("renegotiation.support", reneg_support)
        rating_color = helper.rating2color(self.color, rating_renegotiation)
        print("TLS renegotiation:")
        print(
            "  Supported: {1}{0}{2}".format(
                "yes" if reneg_support else "no",
                rating_color,
                self.color.RESET
            )
        )

        reneg_secure = kb.get("server.renegotiation.secure")
        rating_renegotiation = self._rating.rate("renegotiation.secure", reneg_secure)
        rating_color = helper.rating2color(self.color, rating_renegotiation)
        print(
            "  Secure: {1}{0}{2}".format(
                "yes" if reneg_secure else "no",
                rating_color,
                self.color.RESET
            )
        )
        print("")

    def _print_server_preferred_ciphers(self, kb):
        ciphers = kb.get("server.preferred_ciphers")
        if ciphers is None:
            return

        print("Preferred Server Cipher(s):")
        for cipher in ciphers:
            rating_bits = self._rating.rate('cipher.bits', cipher)
            rating_method = self._rating.rate('cipher.method', cipher)
            rating_name = self._rating.rate('cipher.name', cipher)
            print(
                "  {4}{0:7}{7} {5}{1:>9}{7} {6}{2}{7} {3}".format(
                    cipher.method_name,
                    "%d bits" % cipher.bits,
                    cipher.name,
                    "", # alert info
                    helper.rating2color(self.color, rating_method),
                    helper.rating2color(self.color, rating_bits),
                    helper.rating2color(self.color, rating_name),
                    self.color.RESET
                )
            )
        print("")

    def _print_server_session(self, kb):
        if len(kb.get_list("server.session.")) == 0:
            return

        print("Session:")
        compression = kb.get("server.session.compression")
        if compression is not None:
            if not compression:
                compression = "None"
            print("  Compression: {0}".format(compression))

        expansion = kb.get("server.session.expansion")
        if expansion is not None:
            if not expansion:
                expansion = "None"
            print("  Expansion: {0}".format(expansion))

        print("")

    def run(self):
        kb = self._scanner.get_knowledge_base()

        self._rating = self._scanner.load_rating(self.config.get_value("rating"))

        self._print_client_ciphers(kb)

        self._print_server_ciphers(kb)

        self._print_server_preferred_ciphers(kb)

        self._print_server_certificate(kb)

        self._print_server_session(kb)

        self._print_host_renegotiation(kb)

        self._print_custom(kb, "server.custom")
        self._print_custom(kb, "vulnerability.custom")

modules.register(Terminal)
