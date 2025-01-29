## ReplaceMe Hack The Box Exploit and Walkthrough

Hi! This is a working exploit to the Hack The Box challenge ReplaceMe


# Files

- exploit.py - This is the exploit which uses pwntool
- ghidra/ - This is the Ghidra project I used to reverse engineer the binary


# Walkthrough

Unzipping the zip gives us 5 files, a libc file and a binary file, a test flag and 2 docker related files

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/1.png)

Looking at the binary type we can tell it’s a 64-bit ELF, with PIE (Position Independent Executable) protection.
PIE will load the executable at a random memory address, so we will have to find the base addresses while the program is executing.
The file is also not stripped, which will help when reverse engineering it.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/2.png)

Opening the binary in Ghidra we can have a look at the main function

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/3.png)

We can see it takes 2 inputs of max length 0x80. It's stores the first in the global variable input and the second the address of the global variable replacement

Looking closer at the 2 global variables we can see that input is an array of bytes of size 128

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/4.png)

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/5.png)

Whereas replacement is a single byte, followed by 127 null bytes in memory

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/6.png)

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/7.png)

Next, we can look at the do_replacement function. However, this one is quite hard to read at first, so we can rename the variables to make it easier to understand.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/8.png)

It declares several variables, including a string buffer of size 16, which is zero-initialised manually.
Other variables store pointers and sizes for search and replacement strings.
Validation of Input Format

It checks whether the replacement string starts with "s/" (similar to sed syntax). If not, it throws an error.
It searches for the first /, which separates the old (search) string from the new (replacement) string.
If a / is missing, it raises an error.
Extracting Search and Replacement Strings

It extracts the search string length.
It extracts the replacement string by locating the next /.
If the second / is missing, it throws an error.
Searching for the Target String in Input

It looks for the old (search) string in input.
If the old string is not found, it raises an error.
Performing the Replacement

It calculates the length of the remaining string after the match.
It copies the portion of input before the match into string.
It then copies the replacement string into string at the matched position.
If there's text after the matched portion, it appends it after the replacement string.
Outputting the Result

If successful, it prints "Thank you! Here is the result:" followed by the modified string.

We can buffer overflow the string buffer, as it is only 16 bytes. Both input and replacement could potentially have up to 128 bytes of data, and when combines with the do_replacement function could be even greater.

If we disassemble do_replacement in GDB we find ret at do_replacement+602, we will use this as a break point and inspect the stack

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/9.png)

If we then use pwntools to join to join a large string and a cyclic pattern we will be able to find the offset of the return address

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/10.png)

Once we get to ret in do_replacement we can inspect the stack

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/11.png)

We can take the first 4 chars at the top of the stack to find the offset

We can use the metasploit script to find the offset is 78

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/12.png)

We can then test to see if this is correct, by putting 8 'C's after the offset

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/13.png)

And we can see we have 8 "C" at the top of the stack, followed then by the return character.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/14.png)

However, there is a problem, we don't know the exact address of any functions as PIE is enabled. The address will change each time the program is run.

But, the final bytes of the address might stay the same as the function will have the same offsets.

If I run the program a few times and disassemble the main function we can try and find it out.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/15.png)
![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/16.png)
![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/17.png)

We can see that the main function always ends in the byte 0x4e.

If we inspect the stack at the end of do_replacement without overflowing the buffer we can see what the return address is. It will be near the end of the main function.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/18.png)

We just need to change the the last byte to 0x4e to get the program to return back to the start of the main function.

However, earlier we saw it also adds a line return byte at the end so we will need to terminate the string will a null byte as well.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/19.png)

If we then run this, we can see we have successfully changed the return address to the start of main.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/20.png)

And when we continue, we get asked for our input again.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/21.png)

I also noticed when we overflowed the buffer to the ret address we received a few additional bytes back when the program gives us our final result.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/22.png)

This is likely due to the string not being null terminated so the program continues to output bytes from the stack until it reaches another null byte.

So this would also include the rest of the return address. So if we disassemble the main function, we can see the bytes are the same.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/23.png)

We can use this to find the base address of the executable.

We can subtract the offset of the main function from the leaked address to find the base.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/24.png)

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/25.png)

From this we will be able to find the address of every other function in the program and now enabled us to do ROP.

Our end goal is to gain a shell, included in the files was a Libc library. As libc contains the string "/bin/sh" and has a system function to execute commands, we will be able to gain a shell.

However, we currently don't know the base address of Libc, so we will have to leak it using ROP.

We can try using Puts from the PLT to print out the address of Puts GOT, which will give us the address of Puts in Libc. From there we can subtract the offset of puts to get the address of Libc.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/26.png)

However, when we run this it doesn't output any address. This is because the input variable is a effectively a string and a null byte will terminate it. The ROP chain contains null bytes so we will have to use the replacement variable, as this is an array.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/27.png)

When we try and run this, it crashes.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/28.png)

We can see it crashes while doing the final memcpy.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/29.png)

We might be overflowing some of the variable that are given to this function.

We can set a break point at the memcpy to look into it further.

The first time around it works.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/30.png)

But once we get to the second overflow, we can see the register $rdx (which corresponds to the number of bytes to be replaced) has been corrupted by "C"s.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/31.png)

It looks like we can skip the final memcpy if we can manage to set the "len_after_match" (which is $rdx) variable to 0.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/32.png)

To find out the offset to this variable we can once again utilise a cyclic pattern.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/33.png)

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/34.png)

We see that the $rdx register is now 0x33614132, and find out the offset is 8.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/35.png)

From this, we can set the $rdx register to 0 to skip the final memcpy altogether.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/36.png)

Now when we run the exploit, we can see additional bytes are printed and we return back to the start of main.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/37.png)

If we disassemble puts in GDB we can see the address is the same as the bytes that are printed out

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/38.png)

Using the leaked address of puts, we can work out the base address of Libc. From this we can find the address of system and "bin/sh"

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/39.png)

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/40.png)

From this we can construct a ROP chain to call the system function with the parameter "/bin/sh"

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/41.png)

After running the exploit we can test if we have a shell by running the command "whoami"

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/42.png)

And we receive a response, we have successfully gained a shell.

From here we can print out the flag.

![](https://raw.githubusercontent.com/jzodn/ReplaceMe_HTB/refs/heads/main/imgs/43.png)
