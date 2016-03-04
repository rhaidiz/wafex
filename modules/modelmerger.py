#!/usr/bin/env python
# -*- coding: utf-8 -*-

def merger(webapp_spec,base="./models/base_env.aslan++"):
    output_file_path = "tmp_output.aslan++"
    base_file = open(base,"r")
    webapp_file = open(webapp_spec,"r")
    output_file = open(output_file_path,"w")

    for bline in base_file:
        if "@merge_symbols" in bline:
            for wline in webapp_file:
                if "__webapp" in wline:
                    # stop
                    break
                elif "__symbols" not in wline:
                    output_file.write(wline)

        elif "@merge_webapp" in bline:
            for wline in webapp_file:
                if "__body" in wline:
                    # stop
                    break
                elif "__webapp" not in wline:
                    output_file.write(wline)
        elif "@merge_body" in bline:
            for wline in webapp_file:
                if "__goals" in wline:
                    break
                elif "__body" not in wline:
                    output_file.write(wline)

        elif "@merge_goals" in bline:
            for wline in webapp_file:
                if "__goals" in wline:
                    # stop
                    break
                elif "__webapp" not in wline:
                    output_file.write(wline)

        else:
            output_file.write(bline)
        
    base_file.close()
    webapp_file.close()
    output_file.close()
    return output_file_path

if __name__ == "__main__":
    b = "/Users/federicodemeo/Desktop/regis/PhDStudents/demeo/SQLi-formalization/wsfast/models/"
    merger(b+"test_webapp.aslan++",base=b+"base_env.aslan++")
