package bytes

func And(a, b []byte) []byte {
	var s,l []byte
	if len(a) > len(b) {
		l = a
		s = append([]byte(nil), b...)
	} else {
		s = append([]byte(nil), a...)
		l = b
	}
	for i,_ := range s {
		s[i] &= l[i]
	}
	return s
}

func Or(a, b []byte) []byte {
	var s,l []byte
	if len(a) > len(b) {
		l = append([]byte(nil), a...)
		s = b
	} else {
		s = a
		l = append([]byte(nil), b...)
	}
	for i,_ := range s {
		s[i] |= l[i]
	}
	return l
}
