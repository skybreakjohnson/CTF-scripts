import sys
import codecs

# simple rot13 encoder

if sys.argv[1] == '--help' or sys.argv[1] == '-h':
    print('Usage: python rot13.py <hash>')
    exit(0)
else:
    print(codecs.encode(sys.argv[1], "rot13"))
