import os
import dgl
from dgl import load_graphs
from dgl.data.utils import load_info
from dgl import save_graphs
from dgl.data.utils import save_info
import random
import hashlib
import heapq
import json
import argparse
import warnings
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from scipy.spatial.distance import pdist
from multiprocessing import Process, JoinableQueue
from torch import exp
from utils import *

def consumer(q, in_dir):
    tshark_dir = os.path.join(in_dir,"tsharkjson")
    out_dir = os.path.join(in_dir,"analysis")
    if not os.path.exists(tshark_dir):
        os.mkdir(tshark_dir)
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)
    while True:
        pcap=q.get()
        pcap_dir = os.path.join(tshark_dir,pcap+'.json')
        data = os.system(f"tshark -T json -r {os.path.join(in_dir,pcap)} > {pcap_dir}")
        with open(pcap_dir,'r',encoding='utf8') as f:
            streams = json.load(f, object_pairs_hook=my_obj_pairs_hook)
            print(pcap)
            print(out_dir)
            parse_pcap_json(out_dir, pcap, streams)
            print("%s raw feature extraction finished." %(pcap))
        q.task_done()
        data = os.system(f"rm {pcap_dir}")


def producer(q, in_dir):
    pcaps = os.listdir(in_dir)
    for pcap in pcaps:
        q.put(pcap)
    q.join()

def heatkernel(i,j,t):
    return exp((torch.norm(i-j)**2)/t)

def construct_g(image_f, vectorized_f):
    return

def get_feature(in_dir):
    begin_time = time.time()
    q = JoinableQueue()
    p = Process(target=producer, args=(q,in_dir,))

    p.start()
    for i in range(10):
        c = Process(target=consumer, args=(q,in_dir,))
        c.daemon = True
        c.start()
    p.join()
    end_time = time.time()
    print("Raw feature extraction took %d minutes." % ((end_time - begin_time) / 60))

def load_g(args):
    path = args['dataset']
    device = args['device']
    graph_path = os.path.join(path, 'GenHan_dglgraph.bin')
    graphs, label_dict = load_graphs(graph_path)
    graphs = graphs[0].to(device)
    labels = label_dict['labels'].to(device)
    info_path = os.path.join(path, 'GenHan_info.pkl')
    info = load_info(info_path)
    features = info['features'].to(device)
    num_nodes = features.shape[0]
    num_classes = info['num_classes']
    graphs = dgl.metapath_reachable_graph(graphs, ['recordSimilarity'])

    node_id = [i for i in range(features.shape[0])]
    train_id = random.sample(node_id, (int(len(node_id) /3)))
    val_id = random.sample(node_id, (int(len(node_id) / 3)))
    test_id = random.sample(node_id, (int(len(node_id) / 3)))
    train_mask = getmask(train_id, len(node_id))
    val_mask = getmask(val_id, len(node_id))
    test_mask = getmask(test_id, len(node_id))
    return graphs, features, labels, num_nodes, num_classes, train_id, val_id, test_id, train_mask, val_mask, test_mask, (int(len(node_id) / 3)),

get_feature('/data1/hyp/MCFP/dataset')