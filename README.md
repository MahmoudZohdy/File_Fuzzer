# File_Fuzzer

This is the C++ version of the File Fuzzer Code from Gray Hat Python Book.

It's not smart with known File format(like PE,PDF, Docs,...) , it treats the file as raw data.

```
Usage: File_Fuzzer.exe -e <Executable Path> -x <File Extension>


Create a Directory with the name "examples" in the same place as the executable,

the created directory will contain all the files that will be used in fuzzing.
```

