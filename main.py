import json
from flask import Flask,render_template,request
from flask_apscheduler import APScheduler
import uuid

from websocket import create_connection as connect

import requests
from flask_cors import CORS
import base58
import ecdsa
import hashlib
import time
import codecs
from solathon.core.instructions import transfer

from solathon import Client, Keypair,PublicKey,Transaction
client = Client("https://api.devnet.solana.com")

coin_gecko_ids={"SOL":"solana"}

import hashlib

import secrets

def get_detais_from_key(key):
  key_bytes=codecs.decode(key,"hex")
  pub_key = ecdsa.SigningKey.from_string(key_bytes,curve=ecdsa.SECP256k1).verifying_key.to_string()
  pub_key_hex=codecs.encode(pub_key,"hex")
  pub_key_str=(b'16'+pub_key_hex).decode()
  a1=hashlib.sha512(pub_key_str.encode()).hexdigest()
  a2=hashlib.new("ripemd160",a1.encode()).hexdigest()
  modified_key_hash = "06" + a2
  sha = hashlib.sha512()
  hex_str = modified_key_hash.encode()
  sha.update(hex_str)
  sha_2 = hashlib.sha512()
  sha_2.update(sha.digest())
  checksum = sha_2.hexdigest()[:8]
  byte_address = modified_key_hash + checksum
  address = base58.b58encode(bytes(byte_address.encode())).decode('utf-8')
  return [key,key,pub_key_str,address]


with open("config.json") as f:
    config=json.load(f)
with open("database.json") as f:
    database=json.load(f)

def get_demand():
    demand=0
    for k in database['buy'].keys():
        a=database["buy"][k]
        demand+=a['value']
    if float(demand)==0.0:
        demand=1
    return demand
def get_supply():
    supply=0.0
    for k in database['pools'].keys():
        a=database["pools"][k]
        wallet=get_detais_from_key(a["keyPairs"]['UCC'])
        url = 'ws://localhost:8000'
        websocket=connect(url)
        websocket.send("GET_BALANCE;"+wallet[3])
        message = websocket.recv()
        websocket.close()
        balance=int(message.split(";")[1])/1000000000
        supply+=balance
    for a in database['sell']:
        supply+=a['value']
    if float(supply)==0.0:
        supply=1
    return supply
app= Flask(__name__)
CORS(app)
@app.route("/")
def root():
    return render_template("docs.html")
@app.route("/stats")
def stats():
    url = 'ws://localhost:8000'
    websocket=connect(url)
    websocket.send("GET_SUPPLY")
    message = websocket.recv()
    websocket.close()
    circulation=int(message.split(";")[1])/1000000000
    database['coin-info']['total-circulation']=circulation
    
    price = get_demand() / get_supply()
    
    return {"price-usd":price,"circulation":circulation,"market-cap":price*circulation}
@app.post("/open_pool")
def open_pool():
    data=json.loads(request.data)
    pool_data=json.loads(base58.b58decode(data['pool']).decode())
    if not 10000>=pool_data['max']>=10:
        return "MAX EXCHANGE VALUE MUST BE MORE THAN 10 BUT LESS THAN 10000"
    if not len(pool_data['exchangePairs'].split("|"))==2 or not pool_data['exchangePairs'].split("|")[0]=="UCC":
        return "PLEASE PROVIDE A VALID EXCHANGE PAIR"
    if not pool_data['pubKey']:
        return "PLEASE PROVIDE A PUBLIC KEY"
    if not pool_data['addresses']:
        return "PLEASE PROVIDE CURRENCY ADDRESSES"
    pool_data['hash']=hashlib.sha512(f"{json.dumps(pool_data['addresses'])}{pool_data['max']}{pool_data['exchangePairs']}{pool_data['pubKey']}".encode()).hexdigest()
    if pool_data['exchangePairs'].split("|")[1]=="SOL":
        poolKeys=Keypair()
        key=hex(secrets.randbits(256))[2:]
        if len(key)!=64:
            while len(key)!=64:
                key=hex(secrets.randbits(256))[2:]
        solkey=poolKeys.private_key
        pool_data['keyPairs']={"UCC":key,"TOKEN":str(solkey)}
        pool_UCC=get_detais_from_key(pool_data['keyPairs']['UCC'])[-1]
        pool_TOKEN=str(poolKeys.public_key)
    pool_data['id']=str(uuid.uuid4())
    pool_data['pendingFees']=0
    pool_data['history']=[]
    pool_data['creationTime']=time.time()
    database['pools'][pool_data['id']]=pool_data
    with open("database.json","w") as f:
        json.dump(database,f)
    msg="SEND FUNDS TO THE 2 FOLLOWING ADDRESSES"+pool_data['exchangePairs'].split("|")[0]+": "+pool_UCC+"   |   "+pool_data['exchangePairs'].split("|")[1]+": "+pool_TOKEN
    return msg

@app.route("/buy",methods=["POST"])
def buy():
    data=json.loads(request.data)
    order={"address":data['address'],"currency":data['currency'],"value":data['amount']}
    if order['currency']=='SOL':
        filled=False
        for k in database['pools'].keys():
            a=database['pools'][k]
            wallet=get_detais_from_key(a["keyPairs"]['UCC'])
            url = 'ws://localhost:8000'
            websocket=connect(url)
            websocket.send("GET_BALANCE;"+wallet[3])
            message = websocket.recv()
            websocket.close()
            if not float(message.split(";")[1])>=order['value']:
                pass
            if a['exchangePairs'].split("|")[1]==order['currency']:
                price = get_demand() / get_supply()
                pay_usd=order['value']*price
                currency_price=requests.get("https://api.coingecko.com/api/v3/simple/price?vs_currencies=usd&ids="+coin_gecko_ids[order['currency']]).json()['solana']['usd']
                per_dollar=1/currency_price
                pay_amount=per_dollar*pay_usd
                order['pay_amount']=round(pay_amount*1.1,9)
                if order['currency']=="SOL":
                    payAccount=Keypair()
                    order['payAccount']={"address":str(payAccount.public_key),"key":str(payAccount.private_key)}
                order['created']=time.time()
                order['expire']=order['created']+3600
                order['filled']=True
                order['id']=str(uuid.uuid4())
                order['pool_id']=a['id']
                database['buy'][order['id']]=order
                filled=True
                with open("database.json","w") as f:
                    json.dump(database, f)
                break
        if not filled:
            order['filled']=False
            order['id']=str(uuid.uuid4())
            database['buy'][order['id']]=order
            with open("database.json","w") as f:
                json.dump(database,f)
        return {"result":True,"info":{"pay_amount":order['pay_amount'],"pay_address":order['payAccount']['address']}}
    return {'result':False,"reason":"Currency not available!"}

def check_orders():
    with open("database.json") as f:
        datab=json.load(f)
    ind=0
    completed_orders=[]
    changed_pool={}
    for ok in datab['buy'].keys():
        a=datab['buy'][ok]
        if a['filled']:
            if a['currency']=="SOL":
                orderKeys=Keypair().from_private_key(a['payAccount']['key'])
                if client.get_balance(PublicKey(str(orderKeys.public_key)))['result']['value']>=a['pay_amount']:
                    pool=None
                    for pk in datab['pools'].keys():
                        p=datab['pools'][pk]
                        if a['pool_id']==p['id']:
                            pool=p
                            break
                    poolKeys=Keypair().from_private_key(pool['keyPairs']['TOKEN'])
                    amount=client.get_balance(PublicKey(str(orderKeys.public_key)))['result']['value']-5000
                    instruction = transfer(
                        from_public_key=orderKeys.public_key,
                        to_public_key=PublicKey(str(poolKeys.public_key)), 
                        lamports=amount
                    )
                    transaction = Transaction(instructions=[instruction], signers=[orderKeys])
                    result = client.send_transaction(transaction)
                    print(result)
                    if result['result']:
                        key_bytes=codecs.decode(pool['keyPairs']['UCC'],"hex")
                        pub_key = ecdsa.SigningKey.from_string(key_bytes,curve=ecdsa.SECP256k1).verifying_key.to_string()
                        pub_key_hex=codecs.encode(pub_key,"hex")
                        pub_key_str=(b'16'+pub_key_hex).decode()
                        a1=hashlib.sha512(pub_key_str.encode()).hexdigest()
                        a2=hashlib.new("ripemd160",a1.encode()).hexdigest()
                        modified_key_hash = "06"+a2
                        sha = hashlib.sha512()
                        hex_str = modified_key_hash.encode()
                        sha.update(hex_str)
                        sha_2 = hashlib.sha512()
                        sha_2.update(sha.digest())
                        checksum = sha_2.hexdigest()[:8]
                        byte_address = modified_key_hash + checksum
                        address = base58.b58encode(bytes(byte_address.encode())).decode('utf-8')

                        data_to_sign=hashlib.sha256((pub_key_str+a2+str(a['value']*1000000000)+""+address+a['address']).encode()).digest()

                        sk=ecdsa.SigningKey.from_string(key_bytes,curve=ecdsa.SECP256k1)
                        signature=sk.sign_digest(data_to_sign)
                        sig_hex=codecs.encode(signature,"hex").decode()

                        transdata={"scriptSig":{"sig":sig_hex,"pub":pub_key_str},"hashed_pub":a2,"value":a['value']*1000000000,"message":"","in":address,"out":a['address'],"data":pub_key_str+a2+str(a['value']*1000000000)+""+address+a['address']}
                        url = 'ws://localhost:8000'
                        websocket=connect(url)
                        websocket.send("SEND;"+json.dumps(transdata))
                        websocket.close()
                        a['completed']=result['result']
                        datab['pools'][pool['id']]["pendingFees"]+=5000
                        datab['pools'][pool['id']]['history'].append(a)
                        changed_pool[pool['id']]=datab['pools'][pool['id']]
                        completed_orders.append(a)
        ind+=1      
        if ind>=30:
            break
    #for a in completed_orders:
      
scheduler = APScheduler()
scheduler.add_job(func=check_orders, args=[], trigger='interval', id='job', seconds=30)
scheduler.start()
app.run(host="0.0.0.0",port=4000)
