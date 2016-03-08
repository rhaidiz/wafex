#!/usr/bin/env python
# -*- coding: utf-8 -*-

def merger(file1,file2,out="out.txt"):
    # open the first file and create a structure in memory 
    # to be used for the merging
    m = {}
    with open(file1,"r") as f1:
       tag = ""
       for line in f1:
           if line.strip().startswith("@"):
               tag = line.strip().rstrip()
               if tag not in m:
                   m[tag] = ""
           elif tag != "":
               m[tag] = m[tag] + line
    # merging by substitution
    with open(file2,"r") as f2, open(out,"w") as o:
        for line in f2:
            if line.strip().startswith("@"):
                tag = line.strip().rstrip()
                try:
                    o.write(m[tag])
                except KeyError:
                    o.write("")
            else:
                o.write(line)
    return out

if __name__ == "__main__":
    merger("file2.txt","file1.txt")
