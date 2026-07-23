# The 5G modules use fully-qualified ``fiveg.*`` imports, so - unlike the GTP
# package - they do NOT put this directory on sys.path.  That keeps the generic
# sub-package names (attacks, commons) from colliding with the GTP package's
# top-level names.
