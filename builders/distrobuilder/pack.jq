# pack-lxc repeats repository/package management: remove all build-time mutations.
.packages = {manager:"apt",update:false,cleanup:false,sets:[],repositories:[]} |
del(.actions,.files)
