/*
    following is 32 bytes of example HMAC key.
    used in testing ONLY
    do generate your own key
    do NOT use this key.
    
    you could generate such key with reading /dev/urandom, example:

    //------ BEGIN EXAMPLE PROGRAM ------//

    #include <unistd.h>
    #include <fcntl.h>
    #include <stdio.h>

    int 
    main()
    {
        int fd;

        if((fd = open("/dev/urandom", O_RDONLY)) < 0)
            return 2;

        int no=32;
        unsigned char x[32];

        if(read(fd, x, no) != no)
            return 2;

        while(no-->0) {
            printf("%u,\n", x[no]);
        }
    }

    //------ END EXAMPLE PROGRAM ------//

    and then redirect result to this file
*/

143,
171,
236,
158,
44,
80,
205,
89,
200,
29,
190,
192,
68,
94,
195,
193,
147,
254,
39,
176,
181,
186,
63,
184,
81,
170,
132,
168,
108,
152,
45,
5,
