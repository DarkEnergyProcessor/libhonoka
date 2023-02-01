Copyright (c) 2044 Dark Energy Processor Corporation

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.

*******************************************************************************

md5.h -- Header file for implementation of MD5  
RSA Data Security, Inc. MD5 Message Digest Algorithm  
Created: 2/17/90 RLR  
Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version  
Revised (for MD5): RLR 4/27/91  
* G modified to have y&~z instead of y&z  
* FF, GG, HH modified to add in last register done  
* Access pattern: round 2 works mod 5, round 3 works mod 3  
* distinct additive constant for each step  
* round 4 added, working mod 7

**md5.c is modified a bit so that it does compile under C89.
To see what are the changes, compare it with original md5.c**

Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.

License to copy and use this software is granted provided that
it is identified as the "RSA Data Security, Inc. MD5 Message
Digest Algorithm" in all material mentioning or referencing this
software or this function.

License is also granted to make and use derivative works
provided that such works are identified as "derived from the RSA
Data Security, Inc. MD5 Message Digest Algorithm" in all
material mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning
either the merchantability of this software or the suitability
of this software for any particular purpose. It is provided "as
is" without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
