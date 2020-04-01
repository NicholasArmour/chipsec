from chipsec import chipset
from argparse import *
import glob
import os



def find_chipsec_configs(configs):
    # all the .xml files in chipsec/cfg/
    chipsec_xml = glob.glob(os.path.join('chipsec','cfg','*.xml'))

    found_files = []
    for xml_file in configs:
        cfg = next((f for f in chipsec_xml if xml_file in f), None)
        if cfg == None:
            print( "could not find {} within chipsec/cfg/")
            continue
        found_files.append(cfg)
    
    return found_files
        
def main():

    #init argparse
    parser = ArgumentParser()
    parser.add_argument('-a', '--first_config', nargs='+')
    parser.add_argument('-b', '--second_config', nargs='+')
    args = parser.parse_args()

    # create first_config Chipset object
    custom_xml = find_chipsec_configs(args.first_config)
    first_cs = chipset.cs()
    first_cs.init(None, None, start_driver=False,custom_xml=custom_xml)
    first_registers = set(first_cs.Cfg.REGISTERS.keys())
    #print("{} registers: {}\n\n".format(args.first_config,first_registers))
    
    # create second_config Chipset object
    custom_xml = find_chipsec_configs(args.second_config)
    second_cs = chipset.cs()
    second_cs.init(None, None, False,custom_xml=custom_xml)
    second_registers = set(second_cs.Cfg.REGISTERS.keys())
    #print("{} registers: {}\n\n".format(args.second_config,second_registers))


    #print("{}\n\n{}\n".format(first_registers,second_registers))

    print("{}".format(second_registers - first_registers))
        







main()