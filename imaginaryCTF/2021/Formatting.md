# Formatting

The challenge is a python file. If we run the service using the netcat utility and give some random input, it returns the same string. After reading the source code, I found that format string is used to return the string. 
There is vulnerability in str format in python. You can read more about it [here](https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/).
We can exploit to format string to get the global variable. Use the following payload.

```
hello_{a.__init__.__globals__}
```

and we get the flag

`flag: ictf{c4r3rul_w1th_f0rmat_str1ngs_4a2bd219}`
