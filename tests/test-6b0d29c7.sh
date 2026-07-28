if [ -z "$(which bash)" ] || [ -z "$(which timeout)" ] || [ -z "$(which yes)" ] || [ -z "$(which head)" ]; then
    exit 125;
fi

# proot must not hand an inherited "SIGPIPE ignored" disposition to the
# guest: SIG_IGN survives fork(2) and execve(2), and Android's zygote
# leaves SIGPIPE ignored, so every guest process would see write(2) fail
# with EPIPE instead of being killed quietly -- `yes | head -1` printing
# "yes: standard output: Broken pipe" instead of nothing.
#
# 141 = 128 + SIGPIPE, i.e. the writer was killed as it is without proot.

STATUS=$(bash -c "trap '' PIPE; timeout 10 ${PROOT} bash -c 'yes | head -1 > /dev/null; echo \${PIPESTATUS[0]}'")

if [ "${STATUS}" != "141" ]; then
    exit 1
fi

exit 0
