# freenote-0ctf-2015

freenote is the binary, sploit2 is the exploit.
Uses offsets hardcoded for my system, change before use.

# Synopsis
1) Double free possible because the delete_note() func does not zero out the note pointer.

2) Use double free to free a reallocated in-use note.

3) Leak heap using list_notes().

4) Do this again and overwrite *next with calculated address of a note ptr.

5) Modify the note ptr to point to 0x602070 which is atoi@got.plt.

6) Leak &atoi using list_notes() and calculate address of system() and those of stdout and stdin for repair purposes.

7) Overwrite &atoi with &system and repair stdin and stdout @got.plt

8) Send "/bin/sh\x00" and spawn shell.
