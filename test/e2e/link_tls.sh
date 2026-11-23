# Sourced by the e2e scripts that link two hubs over TCP.
#
# Hub links run over TLS and authenticate by pinned key (link_keys), so each
# hub needs a certificate and the other's link key. Hub "a" gets the test
# certificate from autotest/; hub "b" gets one made here, so the two keys
# differ and each pin is checked for real.
#
#   link_tls_setup DIR      -- make the certificates, learn both link keys
#   link_tls_conf a|b       -- the config lines for that hub
#
# Clients in these scripts still log in over plain adc://, so the hubs set
# tls_require = 0; what is under test is the link, not the client transport.
# Needs $UHUB and $REPO, and the openssl command line tool.

link_tls_setup() {
	local dir=$1
	LT_CERT_a=$REPO/autotest/tls-test-cert.pem
	LT_KEY_a=$REPO/autotest/tls-test-key.pem
	LT_CERT_b=$dir/link-b-cert.pem
	LT_KEY_b=$dir/link-b-key.pem
	command -v openssl >/dev/null || { echo "MISSING: openssl"; exit 2; }
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$LT_KEY_b" -out "$LT_CERT_b" -days 2 -subj /CN=uhub-e2e-b >/dev/null 2>&1 \
		|| { echo "could not create a certificate for hub b"; exit 2; }
	local n
	for n in a b; do
		eval "printf 'tls_certificate = %s\ntls_private_key = %s\n' \"\$LT_CERT_$n\" \"\$LT_KEY_$n\"" > "$dir/linkkey_$n.conf"
		eval "LT_LINKKEY_$n=\$(\"\$UHUB\" -K -c \"$dir/linkkey_$n.conf\" 2>/dev/null)"
		case "$(eval "echo \"\$LT_LINKKEY_$n\"")" in
			SHA256/*) ;;
			*) echo "could not read the link key of hub $n (uhub -K)"; exit 2;;
		esac
	done
}

link_tls_conf() {
	local me=$1 other
	[ "$me" = a ] && other=b || other=a
	eval "echo \"tls_enable = 1\""
	echo "tls_require = 0"
	eval "echo \"tls_certificate = \$LT_CERT_$me\""
	eval "echo \"tls_private_key = \$LT_KEY_$me\""
	eval "echo \"link_keys = \$LT_LINKKEY_$other\""
}
