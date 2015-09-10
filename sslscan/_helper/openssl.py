import six

import flextls

openssl_enabled = False
version_pyopenssl = None
version_openssl = None
try:
    import OpenSSL
    from OpenSSL import SSL
    version_pyopenssl = OpenSSL.__version__
    version_openssl = SSL.SSLeay_version(0)
    if isinstance(version_openssl, six.binary_type):
        version_openssl = version_openssl.decode('ascii')
except ImportError:
    OpenSSL = None


def convert_version2method(protocol_version):
    """
    Convert internal protocol version ID to OpenSSL method.

    :param Integer protocol_version: Version ID
    :return: OpenSSL method or None if not found
    :rtype: OpenSSL method or None
    """
    if protocol_version == flextls.registry.version.SSLv2:
        return SSL.SSLv2_METHOD
    if protocol_version == flextls.registry.version.SSLv3:
        return SSL.SSLv3_METHOD
    if protocol_version == flextls.registry.version.TLSv10:
        return SSL.TLSv1_METHOD
    if protocol_version == flextls.registry.version.TLSv11:
        return SSL.TLSv1_1_METHOD
    if protocol_version == flextls.registry.version.TLSv12:
        return SSL.TLSv1_2_METHOD

    return None

def convert_versions2methods(protocol_versions):
    """
    Convert list of internal protocol version to OpenSSL methods. 
    :param List protocol_version: List of internal protocol version IDs
    :return: List of methods
    :rtype: List
    """

    methods = []
    for protocol_version in protocol_versions:
        method = convert_version2method(protocol_version)
        if method is not None:
            methods.append(method)

    return methods
