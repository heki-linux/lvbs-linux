
def build_tarball_prefix(version):
    return "kernel-mshv-{}".format(version)

def build_tar_name(version):
    tarball_format = "tar"
    return "{}.{}".format(build_tarball_prefix(version), tarball_format)

def build_tgz_name(version):
    tarball_name = "{}.gz".format(build_tar_name(version))
    return tarball_name

