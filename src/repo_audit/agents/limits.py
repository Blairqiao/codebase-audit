"""Fresh process sets resource limits before replacing itself with the audited command."""
import os
import resource
import sys


def main() -> None:
    quota = int(sys.argv[1])
    _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    if hard != resource.RLIM_INFINITY:
        quota = min(quota, hard)
    resource.setrlimit(resource.RLIMIT_NPROC, (quota, quota))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    file_limit = int(sys.argv[2])
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    os.execvpe(sys.argv[3], sys.argv[3:], os.environ)


if __name__ == '__main__':
    main()
