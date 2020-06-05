import mmap
import argparse
from xml.dom import minidom

from Evtx.Evtx import FileHeader
import Evtx.Views


def main():
    parser = argparse.ArgumentParser(prog="evtIdDumper", description="Specify eventID to dump")
    # parser.add_argument("-f", "--iFile", dest="ifile", type=str, required=True, help="path to the input file")
    # parser.add_argument("-i", "--evtId", dest="id", type=str, default="all", help="id of the Event to Dump")
    parser.add_argument("-o", "--oFile", dest="ofile", type=str, required=False, help="path to the output file")

    args = parser.parse_args()
    args.ifile = "Security.evtx"
    args.evtId = "4624"
    args.ofile = 'security.txt'
    args.logontype = '10'

    outFile = False
    if args.ofile is not None:
        outFile = open(args.ofile, 'a+')
    with open(args.ifile, 'r') as f:
        buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        fh = FileHeader(buf, 0x00)
        hOut = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?><Events>"
        if outFile:
            outFile.write(hOut)
        else:
            print(hOut)

        for strxml, record in Evtx.Views.evtx_file_xml_view(fh):
            xmlDoc = minidom.parseString(strxml.replace("\n", ""))
            evtId = xmlDoc.getElementsByTagName("EventID")[0].childNodes[0].nodeValue
            if args.id == 'all':
                if outFile:
                    outFile.write(xmlDoc.toprettyxml())
                else:
                    print(xmlDoc.toprettyxml())

            if evtId == args.evtId:
                if outFile:
                    outFile.write(xmlDoc.toprettyxml())
                else:
                    print(xmlDoc.toprettyxml())

        buf.close()
        endTag = "</Events>"
        if outFile:
            outFile.write(endTag)
        else:
            print(endTag)


if __name__ == '__main__':
    main()