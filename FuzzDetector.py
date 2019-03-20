import os,sys,platform,pickle,gib_detect_train
from scapy.all import *

model_data = pickle.load(open('gib_model.pki', 'rb'))
global_detected = True

def is_gibrish(text):
    model_mat = model_data['mat']
    threshold = model_data['thresh']
    return gib_detect_train.avg_transition_prob(text, model_mat) > threshold

def fuzz_detection(pkt):
    try:
    	global_detected = is_gibrish(str(pkt[3]))
    	if(not global_detected):
		print "Fuzzing Detected"
        	exit()
    except IndexError:
    	return


def __main__():
    while global_detected:
        pkt = sniff(filter="port 22", prn=fuzz_detection)
__main__()
