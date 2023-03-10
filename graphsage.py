import time

import torch
import argparse
import warnings
from dgl.nn.pytorch.conv import SAGEConv
import torch.nn as nn
import torch.nn.functional as F
from utils import *
from datasets import *

parser = argparse.ArgumentParser()
parser.add_argument('--seed', type=int, default=19990708, help='random seed')
parser.add_argument('--lr', type=float, default=0.005, help='learning rate')
parser.add_argument('--weight_decay', type=float, default=100.0, help='weight decay (L2 loss on parameters)')
parser.add_argument('--dataset', type=str, default='../dataset', help='path of dataset')
parser.add_argument('--aggregator', type=str, default='pool', help='path of dataset')
parser.add_argument('--hidden_units', type=int, default=16, help='hidden size')
parser.add_argument('--dropout', type=float, default=0.6, help='dropout rate')
parser.add_argument('--epoch', type=int, default=200, help='number of epochs to train the RHGEN')
parser.add_argument('--patience', type=int, default=25, help='patience for shut down the RHUGSL')
parser.add_argument('-ld', '--log-dir', type=str, default='results', help='Dir for saving training results')
args = parser.parse_args().__dict__
args = setup(args)
class SAGENet(nn.Module):
    def __init__(self, in_dim, out_dim, hidden_dim, aggregator, dropout=0, norm=None, activation=F.relu):
        super(SAGENet, self).__init__()
        self.conv1 = SAGEConv(in_dim, hidden_dim, aggregator, dropout, norm=norm, activation=activation)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim, aggregator, dropout, norm=norm, activation=activation)
        self.clf = nn.Linear(hidden_dim, out_dim)

    def forward(self, g, x):
        # edge_index = g.edges()
        x = self.conv1(g, x)
        x = self.conv2(g, x)
        x = self.clf(x)

        return F.log_softmax(x, dim=1)

graphs, features, labels, num_nodes, num_classes,\
    train_id, val_id, test_id, train_mask, val_mask, test_mask, test_num= load_g(args)
print('num_nodes:{} | num_classes:{}'.format(num_nodes,num_classes))
model = SAGENet(features.shape[1], num_classes, args['hidden_units'], args['aggregator'], dropout=args['dropout']).to(args['device'])
stopper = EarlyStopping(patience=args['patience'])
loss_fcn = torch.nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=args['lr'],
                             weight_decay=args['weight_decay'])
for epoch in range(args['epoch']):
    start = time.time()
    model.train()
    output = model(graphs, features)
    loss = loss_fcn(output[train_mask], labels[train_mask])
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
    train_acc, train_micro_f1, train_macro_f1, train_FPR, train_FNR = score(output[train_mask], labels[train_mask])
    val_loss, val_acc, val_micro_f1, val_macro_f1, val_FPR, val_FNR = evaluate(model, graphs, features, labels, val_mask, loss_fcn)
    early_stop = stopper.step(val_loss.data.item(), val_acc, model, args)
    print(
        'Epoch [{:03d}/{}] | Train Loss {:.4f} | Train Micro f1 {:.4f} | Train Macro f1 {:.4f} | Train FPR {:.4f} | Train FNR {:.4f} | '
        'Val Loss {:.4f} | Val Accuracy {:.4f} | Val Micro f1 {:.4f} | Val Macro f1 {:.4f} | Val FPR {:.4f} | Val FNR {:04f} | Time {:.4f}s'.format(
            epoch + 1, args["epoch"], loss.item(), train_micro_f1, train_macro_f1, train_FPR, train_FNR,
            val_loss.item(), val_acc, val_micro_f1,
            val_macro_f1, val_FPR, val_FNR, time.time() - start))
    if early_stop:
        break
stopper.load_checkpoint(model, args)
print("***********************************************************************************************")
test_start = time.time()
test_loss, test_acc, test_micro_f1, test_macro_f1, test_FPR, test_FNR = evaluate(model, graphs, features, labels, test_mask, loss_fcn)
print('Test loss {:.4f} | Test Accuracy {:.4f} | Test Micro f1 {:.4f} | Test Macro f1 {:.4f} | Test FPR {:.4f} | Test FNR {:.4f} | Time {}s'.format(
    test_loss.item(), test_acc, test_micro_f1, test_macro_f1, test_FPR, test_FNR, (time.time() - test_start)/test_num))


