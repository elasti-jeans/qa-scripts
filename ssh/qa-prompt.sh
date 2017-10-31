function nonzero_return() {
	RETVAL=$?
	[ $RETVAL -ne 0 ] && echo "ERROR=$RETVAL "
}

export PS1="\`nonzero_return\`\D{%d/%m %H:%M:%S} \u@\h \w# "
