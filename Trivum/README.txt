example for encode:
python3 Trivium.py -m e body.bin -oK fordecrypt.txt -oC cipher.bin

example for decode:
python3 Trivium.py -m d cipher.bin -iK fordecrypt.txt -o plain.bin

binary to ppm formating:
copy the first 3 to 4 rows of the ppm to a file, this is the head of the end result
and merge it with the result like so:
cat head.txt body.bin > test.ppm