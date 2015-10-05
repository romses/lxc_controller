#!/usr/bin/python3

# all the imports
import sqlite3
from flask import Flask, request, session, redirect, url_for, abort, render_template, flash
from contextlib import closing
import pymysql as mdb
from lib import lxclite
import lxc
import json
import timestamp
import datetime
import bcrypt
import logging
import urllib
import shutil                   #filecopy
import os
import subprocess,shlex               #execute shell commands
from subprocess import Popen
import time
import tempfile
from functools import wraps
import socket
import tarfile
import _thread


app = Flask(__name__)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in') or ((timestamp()-session['last']) > options['SESSION_EXPIRE']):
            return redirect(url_for('login'))
        session['last']=timestamp()
        return f(*args, **kwargs)
    return decorated

@app.route('/list/container')
@requires_auth
def listcontainer():
    return index()

@app.route('/databases/list')
@requires_auth
def listdatabases():
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()

    entries={'container':[],'databases':[]}
    cur.execute('SELECT user,password,container FROM db')
    rows = cur.fetchall()

    for row in rows:
        c={'name':row[0],
           'password':row[1],
           'container':row[2]
        }
        entries['databases'].append(c)

    con.close()

    for container in lxc.list_containers(as_object=True):
        if (container.name != "_template"):
            entries['container'].append(container.name)

    return render_template('list_databases.tmpl',entries=entries)

@app.route('/backups/list')
@requires_auth
def listbackups():

    #TODO
    entries=[]

    containers=os.listdir(options['BACKUPPATH'])
    sumsize=0

    for container in sorted(containers):
        for filename in os.listdir(options['BACKUPPATH']+"/"+container):
            tokens=filename.split(".")[0]
            tokens=tokens.split("-")
            date=tokens[2]+"."+tokens[1]+"."+tokens[0]+" "+tokens[3]+":"+tokens[4]+":"+tokens[5]
            size=os.stat(options['BACKUPPATH']+"/"+container+"/"+filename)
            size=str(round(size.st_size/(1024*1024),2))
##            date=date.split(".",1)[0]
            c={'container':container,
               'date':date,
               'file':container+"/"+filename,
               'size':size
            }
            entries.append(c)
        

    return render_template('list_backups.tmpl',entries=entries)

@app.route('/backups/delete/<container>/<name>')
@requires_auth
def deletebackup(container,name):
#    print(options['BACKUPPATH']+name)
    os.remove(options['BACKUPPATH']+"/"+container+"/"+name)
    return redirect(request.headers.get("Referer"))

@app.route('/user/list')
@requires_auth
def listusers():
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()


    cur.execute('SELECT userid,passwd,container FROM ftpuser')
    rows = cur.fetchall()

    entries={'user':[],'container':[]}

    for row in rows:
        c={'user':row[0],
           'password':row[1],
           'container':row[2],
        }
        entries['user'].append(c)

    con.close()

    for container in lxc.list_containers(as_object=True):
        if (container.name != "_template"):
            entries['container'].append(container.name)


    return render_template('list_users.tmpl',entries=entries)

@app.route('/domains/list')
@requires_auth
def listdomains():
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()

    entries={'container':[],'domains':[]}
    cur.execute('SELECT domain,www,`ssl`,container,crtfile FROM domains')
    rows = cur.fetchall()

    for row in rows:
        try:
            ip=socket.gethostbyname(row[0])
        except:
            ip="not hosted"
        c={'domain':row[0],
           'www':row[1],
           'ssl':row[2],
           'container':row[3],
           'crtfile':row[4],
           'ip':ip
        }
        entries['domains'].append(c)

    con.close()

    for container in lxc.list_containers(as_object=True):
        if (container.name != "_template"):
            entries['container'].append(container.name)

    return render_template('list_domains.tmpl',entries=entries)


@app.route('/database/add',methods=['POST'])
@requires_auth
def adddatabases():

    if 'user' in request.form.keys():
        user=request.form['user']
    else:
        flash("Error: User not given")
        return redirect(request.headers.get("Referer"))

    if 'password' in request.form.keys():
        password=request.form['password']
    else:
        flash("Error: Password not given")
        return redirect(request.headers.get("Referer"))

    if 'container' in request.form.keys():
        name=request.form['container']
    else:
        flash("Error: Container not given")
        return redirect(request.headers.get("Referer"))

    try:
        con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
        cur = con.cursor()
        cur.execute('INSERT INTO db (user,password,container) VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE password=VALUES(password),container=VALUES(container)',(user,password,name))
        con.commit()
        rows = cur.fetchall()
    except mdb.Error as e:
        logging.warn(e)
    finally:
        con.close()
    updateDatabases()

    return redirect(request.headers.get("Referer"))
#    return redirect('/container/edit/'+name)

@app.route('/database/delete/<name>')
@requires_auth
def deletedatabases(name):
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute('SELECT container FROM db where user=%s',(name))
    rows = cur.fetchall()
    domain=rows[0][0]
    cur.execute('DELETE FROM db where user=%s',(name))
    con.commit()
    rows = cur.fetchall()
    try:
        cur.execute("DROP DATABASE {db}".format(db=name))
        con.commit()
    except mdb.Error as e:
        logging.warn(e)

    try:
        cur.execute("DROP USER %s@'%%'",(name))
        con.commit()
    except mdb.Error as e:
        logging.warn(e)

    con.close()

    return redirect(request.headers.get("Referer"))
#    return redirect('/container/edit/'+domain)


@app.route('/')
@requires_auth
def index():

    entries=[]
    dbentries={}

    try:
        con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
        cur = con.cursor()

        cur.execute('SELECT DISTINCT container FROM ftpuser UNION SELECT container from domains')
        rows = cur.fetchall()

    except:
        flash("Database Error")

    for row in rows:
        dbentries[row[0]]=0

    for container in lxc.list_containers(as_object=True):
        if (container.name != "_template"):
            c={'name':container.name,
               'state':container.state,
               'mem':int(int(lxclite.info(container.name)['mem'])/(1024*1024))
            }
            if container.running:
                c['ip']=container.get_ips(timeout=30)[0]
            if container.name not in dbentries:
                c['warning']='container has no user or domains configured'
            else:
                dbentries.pop(container.name)
            entries.append(c)

    for entry in dbentries:
        cur.execute('DELETE FROM ftpuser where container=%s',entry)
        con.commit()
        cur.execute('DELETE FROM domains where container=%s',entry)
        con.commit()
        logging.info('Cleaning orphaned container %s',entry)


    return render_template('list_containers.tmpl',entries=entries)

@app.route('/lxc/images')
@requires_auth
def getLxcImages():
    f=urllib.request.urlopen(options['IMAGE_URL'])
    lines=f.readlines()
    jsondata={}

    for line in lines:
        dist=line.decode().split(";")[0]
        release=line.decode().split(";")[1]
        arch=line.decode().split(";")[2]
        if dist not in jsondata.keys():
            jsondata[dist]={}
        if release not in jsondata[dist].keys():
            jsondata[dist][release]=[]
        if arch in ("amd64","i386"):
            jsondata[dist][release].append(arch)

    return json.dumps(jsondata, sort_keys=True)

@app.route('/container/edit/<name>')
@requires_auth
def containeredit(name):
    entries = dict(name=name,state=lxclite.info(name))
    entries['state']['mem']=int(int(entries['state']['mem'])/(1024*1024))

    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute('SELECT userid,passwd FROM ftpuser where container= %s',(name))
    rows = cur.fetchall()
    entries['users']=rows

    cur.execute('SELECT * FROM domains where container= %s',(name))
    rows = cur.fetchall()
    entries['domains']=rows

    cur.execute('SELECT user,password FROM db where container= %s',(name))
    rows = cur.fetchall()
    con.close()
    entries['databases']=rows

    return render_template('edit_container.tmpl',entries=entries)

@app.route('/container/add', methods=['POST'])
@requires_auth
def containeradd():
    name=request.form['name']

    if(request.form['type']=='download'):
        dist=request.form['system']
        release=request.form['version']
        arch=request.form['architecture']
        param=' -d '+dist+" -r "+release+" -a "+arch
        cmd=lxclite.create(name,'download','btrfs',param)
    else:
        cmd=lxclite.clone('_template',name)

    f = open("/var/lib/lxc/"+name+"/config","a")
    f.write("lxc.start.auto = 1")
    f.close()

    updateHAProxy()
    return redirect(url_for('index'))

@app.route('/container/delete/<name>')
@requires_auth
def containerdelete(name):
    c=lxc.Container(name)

    if c.defined:
        if not c.shutdown(30):
            logging.warn("Failed to cleanly shutdown the container "+name+"... forcing.")
            if notc.stop():
                logging.error("Failed to kill the container")
        c.destroy()

        updateHAProxy()

    return redirect(url_for('index'))

@app.route('/admin/list')
@requires_auth
def adminlist():
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()

    entries=[]
    cur.execute('SELECT user,password FROM users')
    rows = cur.fetchall()

    for row in rows:
        c={'name':row[0],
           'password':row[1]
        }
        entries.append(c)

    return render_template('list_admins.tmpl',entries=entries)

@app.route('/admin/add',methods=['POST'])
@requires_auth
def adminadd():
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()

    try:
        password=bcrypt.hashpw(request.form['password'],bcrypt.gensalt())
        cur.execute('INSERT INTO users (user,password) VALUES (%s,%s) ON DUPLICATE KEY UPDATE password=VALUES(password)',(request.form['user'],request.form['password']))
        con.commit()    
    except mdb.Error as e:
        logging.warn(e)

    con.close()
    return redirect(url_for('adminlist'))

@app.route('/admin/delete/<name>')
@requires_auth
def admindel(name):
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()

    cur.execute('DELETE FROM users where user=%s',(name))
    con.commit()

    return redirect(url_for('adminlist'))


@app.route('/container/start/<name>')
@requires_auth
def containerstart(name):
    container=lxc.Container(name)
    if container.defined:
        container.start()
        return 'Ok'
    else:
        logging.info("%s not existing",name)
        return 'Error'

@app.route('/container/stop/<name>')
@requires_auth
def containerstop(name):
    container=lxc.Container(name)
    if container.defined:
        logging.info("Stopping %s",name)
        container.stop()
        return "Ok"
    else:
        logging.info("%s not existing",name)
        return 'Error'

@app.route('/user/add', methods=['POST'])
@requires_auth
def useradd():
    if ('user' not in request.form.keys()) or request.form['user']=="":
        flash('User is required')
        return redirect(request.headers.get("Referer"))
    if ('password' not in request.form.keys()) or request.form['password']=="":
        flash('Password is required')
        return redirect(request.headers.get("Referer"))
    if ('container' not in request.form.keys()) or request.form['container']=="":
#        print("Container: ",container)
        flash('container is required')
        return redirect(request.headers.get("Referer"))

    user=request.form['user']
    password=request.form['password']
    container=request.form['container']

    adduser(user,password,container)

    return redirect(request.headers.get("Referer"))



def adduser(user,password,container):
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    homedir="/var/lib/lxc/"+container+"/rootfs/var/www/html/"
    cur.execute('INSERT INTO ftpuser (userid,passwd,container,homedir) VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE passwd=VALUES(passwd)',(user,password,container,homedir))
    con.commit()
    logging.info('User %s added',user)
    rows = cur.fetchall()
    con.close()

@app.route('/user/delete/<name>')
@requires_auth
def deluser(name):
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute('SELECT container FROM ftpuser where userid=%s',(name))
    rows = cur.fetchall()
    domain=rows[0][0]
    cur.execute('DELETE FROM ftpuser where userid=%s',(name))
    con.commit()
    rows = cur.fetchall()
    con.close()
    return redirect(request.headers.get("Referer"))
#    return redirect('/container/edit/'+domain)

@app.route('/container/backup/<container>')
@requires_auth
def backup(container):
    _thread.start_new_thread(_backup,(container,))
    return "Ok Backup started "
    return redirect(request.headers.get("Referer"))


def _backup(container):
    logging.info('Backing up databases '+container)

    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute('SELECT * FROM db WHERE container = %s',(container))
    rows = cur.fetchall()

    command = ['mysqldump', '-u'+options['DB_USERNAME'],"-p"+options['DB_PASSWORD'],"--databases"];

    f=open('/var/lib/lxc/'+container+'/databasedump.sql',"w")
    for row in rows:
        command.append(row[0])
    x=Popen(command,stdout=f)
    x.wait()

    for row in rows:
        sql="INSERT INTO db (user,password,container) VALUES ('{}','{}','{}') ON DUPLICATE KEY UPDATE user=VALUES(user), password=VALUES(password), container=VALUES(container);\n"
        f.write(sql.format(row[0],row[1],row[2]))
        sql="GRANT USAGE ON *.* to '{}'@'%' IDENTIFIED BY '{}';\n"
        f.write(sql.format(row[0],row[1]))
        sql="GRANT ALL ON {}.* to '{}'@'%' IDENTIFIED BY '{}';\n"
        f.write(sql.format(row[0],row[0],row[1]))


    cur.execute('SELECT * FROM ftpuser WHERE container = %s',(container))
    rows = cur.fetchall()

    for row in rows:
        sql="INSERT INTO ftpuser (userid,passwd,container,uid,gid,homedir,shell) VALUES ('{}','{}','{}',{},{},'{}','{}') ON DUPLICATE KEY UPDATE userid=VALUES(userid), passwd=VALUES(passwd), container=VALUES(container), uid=VALUES(uid), gid=VALUES(gid),homedir=VALUES(homedir),shell=VALUES(shell);\n"
        f.write(sql.format(row[0],row[1],row[2],row[3],row[4],row[5],row[6]))

    cur.execute('SELECT * FROM domains WHERE container = %s',(container))
    rows = cur.fetchall()

    for row in rows:
        domain=row[0]
        www=row[1]
        ssl=row[2]
        crtfile=row[3]
        sql="INSERT INTO domains (domain,www,`ssl`,container,crtfile) VALUES ('{}',{},'{}','{}','{}') ON DUPLICATE KEY UPDATE domain=VALUES(domain), www=VALUES(www), `ssl`=VALUES(`ssl`), container=VALUES(container), crtfile=VALUES(crtfile);\n"
        f.write(sql.format(domain,www,ssl,container,crtfile))
    f.close()

    today = datetime.datetime.today()

    filename=options['BACKUPPATH']+"/"+container+"/"+today.strftime("%Y-%b-%d-%H-%M-%S")+".tar.bz2.incomplete"

    if not os.path.isdir(options['BACKUPPATH']+"/"+container+"/"):
        os.mkdir(options['BACKUPPATH']+"/"+container+"/")

    tar=tarfile.open(filename,'w:bz2')
    tar.add('/var/lib/lxc/'+container,filter=prefixer)
    tar.close()

    os.rename(filename,filename.replace('.incomplete','',1))

    os.remove('/var/lib/lxc/'+container+'/databasedump.sql')


    return "Ok"
    return redirect(request.headers.get("Referer"))
    
def prefixer(tarinfo):
    tarinfo.name=tarinfo.name[12:]
    tokens=tarinfo.name.split("/")
    if(len(tokens)>3):
        if(tokens[3]=="proc"):
            return None
        if(tokens[3]=="sys"):
            return None
        if(tokens[3]=="run"):
            return None

    return tarinfo

@app.route('/container/restore/<container>/<file>')
@requires_auth
def restorecontainer(container,file):
    _thread.start_new_thread(_restore,(container,file,))
#    return redirect('/')
    return redirect(request.headers.get("Referer"))

def _restore(container,file):
    cmd='btrfs subvolume list /var/lib/lxc'
    subvolumes=os.popen(cmd).readlines()

    create_subvolume=1

#    container=file.split("-")[0]

    for subvolume in subvolumes:
        if (subvolume.split(" ")[8].strip()) == container:
            create_subvolume=0

    if(create_subvolume):
        if not os.path.isdir("/var/lib/lxc/"+container):
            os.makedirs("/var/lib/lxc/"+container)
        cmd="btrfs subvolume create /var/lib/lxc/"+container+"/rootfs"
        os.popen(cmd)

    today = datetime.datetime.today()

    f=open("/var/lib/lxc/"+container+"/.lockfile","w")
    f.write(today.strftime("%Y-%b-%d-%H-%M-%S"))
    f.close()

    cmd='tar xf '+options['BACKUPPATH']+"/"+container+"/"+file+" -C /var/lib/lxc/"
    os.popen(cmd).readlines()

    f=open("/var/lib/lxc/"+container+"/domains","r")
    domains=f.readlines()
    f.close()

    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()

    for domain in domains:
        tokens=domain.strip().split(";")
        domain=tokens[0]
        www=int(tokens[1])
        tmpfile=tokens[2]
        crtfile=tokens[3]
        try:
            cur.execute('INSERT INTO domains (domain,www,`ssl`,Container,crtfile) VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE www=VALUES(www), `ssl`=VALUES(`ssl`), Container=VALUES(Container)',(domain,www,tmpfile,container,crtfile))
            con.commit()
        except  mdb.Error as e:
            logging.warn("Creating "+row[0]+" failed")
            logging.warn(e)

        rows = cur.fetchall()
    con.close()
    updateHAProxy()

#    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
#    cur = con.cursor()
#    cur.execute('INSERT INTO domains (domain,www,`ssl`,Container) VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE www=VALUES(www), `ssl`=VALUES(`ssl`), Container=VALUES(Contai$
#    con.commit()
#    rows = cur.fetchall()
#    con.close()
#    updateHAProxy()

    os.remove("/var/lib/lxc/"+container+"/.lockfile")

    return "Ok"
    return redirect(request.headers.get("Referer"))

@app.route('/domain/delete/<name>')
@requires_auth
def deldomain(name):
    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute('SELECT container FROM domains where domain=%s',(name))
    rows = cur.fetchall()
    domain=rows[0][0]
    cur.execute('DELETE FROM domains where domain=%s',(name))
    con.commit()
    rows = cur.fetchall()
    con.close()
    updateHAProxy()
    return redirect(request.headers.get("Referer"))
#    return redirect('/container/edit/'+domain)

@app.route('/domain/add', methods=['POST'])
@requires_auth
def adddomain():
    name=''
    domain=''
    www=1
    crt=''

    if 'container' not in request.form.keys():
        flash('Container missing')
        return redirect(request.headers.get("Referer"))
    if 'domain' not in request.form.keys():
        flash('domain missing')
        return redirect(request.headers.get("Referer"))
    if 'www' not in request.form.keys():
        www=0
    if 'certificate' in request.form.keys():
        crt=request.form['certificate']

    name=request.form['container']
    domain=request.form['domain']
    tmpfile='/etc/haproxy/certs/'+domain+".crt"

    if (crt == ""):
        if os.path.isfile(tmpfile):
            os.remove(tmpfile)
        tmpfile=""
    else:
        if not os.path.isfile(crt): #If a crt and not a path is given
            f=open(tmpfile,"w")
            f.write(crt)
            f.close()

    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute('INSERT INTO domains (domain,www,`ssl`,Container) VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE www=VALUES(www), `ssl`=VALUES(`ssl`), Container=VALUES(Container)',(domain,www,tmpfile,name))
    con.commit()
    rows = cur.fetchall()
    con.close()
    updateHAProxy()
    return redirect(request.headers.get("Referer"))
#    return redirect('/container/edit/'+name)

@app.route('/lxc/ls')
@requires_auth
def lxcls():
    return json.dumps(lxclite.ls())

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.pop('logged_in', None)
    session.pop('last', None)
    session.pop('user',None)

    error = None
    if request.method == 'POST':
        con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
        cur = con.cursor()
        cur.execute('SELECT password FROM users where user= %s LIMIT 1',(request.form['username']))
        rows = cur.fetchall()
        if(len(rows)>0):
            if (request.form['password']==rows[0][0]):
                logging.info('Plaintext Password for %s OK encrypting password now.',request.form['username'])
                password=bcrypt.hashpw(request.form['password'],bcrypt.gensalt())
                cur.execute('UPDATE users set password = %s where user = %s;',(password,request.form['username']))
                con.commit()
                rows = cur.fetchall()
                session['logged_in'] = True
                session['last']=timestamp()
                session['user']=request.form['username']
                flash('You were logged in')
                con.close()
                return redirect(url_for('index'))
            elif(bcrypt.hashpw(request.form['password'], rows[0][0]) == rows[0][0]):
                logging.info('BCrypt Password for %s OK',request.form['username'])
                session['logged_in'] = True
                session['last']=timestamp()
                session['user']=request.form['username']
                flash('You were logged in')
                con.close()
                return redirect(url_for('index'))
            else:
                logging.info('Login error')
                session.pop('logged_in', None)
                session.pop('last',None)
                session.pop('user',None)

    return render_template('login.html', error=error)

def updateHAProxy():
    logging.info("Generating HAProxy configuration")
    shutil.copy2('haproxy.stub', '/etc/haproxy/haproxy.cfg')


    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute("SELECT domain,www,`ssl`,container FROM domains")
    rows = cur.fetchall()

    domains={}
    ssldomains={}
    sslcerts=[]
    backends=[]

    for row in rows:
        if(row[3] in lxclite.running()):
            domains[row[0]]=row[3]
            if(row[3] not in backends):
                backends.append(row[3])
            if(row[1]):
                domains['www.'+row[0]]=row[3]
            if(row[2]):
                sslcerts.append(row[2])
                ssldomains[row[0]]=row[3]
                if(row[1]):
                    ssldomains['www.'+row[0]]=row[3]

    f=open('/etc/haproxy/domain2backend.map',"w")
#Generate HTTP Frontends
    for k in domains.keys():
        f.write(k+" bk_"+domains[k]+"\n")
    f.write("macftp02.macrocom.de bk_config\n")
    f.close()

    f=open("/etc/haproxy/domain2backend_ssl.map","w")
    for k in ssldomains:
#         print(k+" "+ssldomains[k])
         f.write(k+" bk_"+ssldomains[k]+"\n")
    f.close()

    f = open("/etc/haproxy/haproxy.cfg","a")

#Generate HTTPS Frontends
    if(len(ssldomains)>0):
        f.write("frontend https\n")
        f.write("\tmode http\n")
        f.write("\tbind 0.0.0.0:443 ssl")
        for k in sslcerts:
            f.write(" crt "+k)
        f.write("\n\tuse_backend %[req.hdr(host),lower,map(/etc/haproxy/domain2backend_ssl.map,bk_default)]\n\n")

#Generate Backends
   
    for k in backends:
        f.write('backend bk_'+k+"\n")
        f.write('\tmode http\n')
        f.write('\tserver '+k+' '+k+'.lxc:80 check\n')
        f.write('\n\n')
    f.write('backend bk_config\n')
    f.write('\tmode http\n')
    f.write('\tserver srvdefault 127.0.0.1:'+options['PORT']+' check\n\n')

    if con:
        con.close()
    if f:
        f.close()

    command = ['service', 'haproxy','restart'];
    subprocess.check_call(command, shell=False)

    return 0

def updateDatabases():
    logging.info("Setting up databases and users")

    con = mdb.connect(options['DB_HOST'], options['DB_USERNAME'], options['DB_PASSWORD'], options['DB']);
    cur = con.cursor()
    cur.execute("SELECT user,password,container FROM db")
    rows = cur.fetchall()

    for row in rows:    
        try:
            cur.execute("CREATE DATABASE IF NOT EXISTS {db}".format(db=row[0]))
            con.commit()
        except  mdb.Error as e:
            logging.warn("Creating "+row[0]+" failed")
            logging.warn(e)

        try:
            cur.execute("CREATE USER %s IDENTIFIED BY %s",(row[0],row[1]))
            con.commit()
        except  mdb.Error as e:
            logging.warn("Warning: User existing. Trying to update password")
            try:
                cur.execute("SET PASSWORD FOR %s@'%%' = PASSWORD(%s)",(row[0],row[1]))
                con.commit()
            except mdb.Error as e:
                logging.warn("Cannot update Password")
                logging.warn(e)

        try:
            cur.execute("GRANT USAGE on *.* TO %s@'%%' IDENTIFIED BY %s",(row[0],row[1]))
            con.commit()
        except  mdb.Error as e:
            logging.warn(e)

        try:
            cur.execute("GRANT ALL ON {user}.* TO %s@'%%' IDENTIFIED BY %s".format(user=row[0]),(row[0],row[1]))
            con.commit()
        except  mdb.Error as e:
            logging.warn(e)
    con.close()

    return 0

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('last', None)
    session.pop('user',None)
    flash('You were logged out')
    return redirect(url_for('login'))

def parse_config(filename):
    COMMENT_CHAR = '#'
    OPTION_CHAR =  '='
    options = {}
    f = open(filename)
    for line in f:
        # First, remove comments:
        if COMMENT_CHAR in line:
            # split on comment char, keep only the part before
            line, comment = line.split(COMMENT_CHAR, 1)
        # Second, find lines with an option=value:
        if OPTION_CHAR in line:
            # split on option char:
            option, value = line.split(OPTION_CHAR, 1)
            # strip spaces:
            option = option.strip()
            value = value.strip()
            # store in dictionary:
            options[option] = value
    f.close()
    # chek and set defaults

    defaults={'DEBUG'         :False,
              'SECRET_KEY'    :'development key',
              'DB_USERNAME'   :'lxc',
              'DB_PASSWORD'   :'secret',
              'DB_HOST'       :'localhost',
              'DB'            :'lxc',
              'SESSION_EXPIRE': 1000*3000,
              'DOMAINNAME'    : 'macftp02.macrocom.de',
              'PORT'          : 5000,
              'LOG'           : '/var/log/lxc-admin.log',
              'LOGLEVEL'      : 'WARNING',
              'IMAGE_URL'     : 'http://images.linuxcontainers.org/meta/1.0/index-system',
              'BIND'          : '127.0.0.1',
              'BACKUPPATH'    : '/var/lib/lxc-backups/'
              }

    for k in defaults.keys():
        options[k]=options[k] if k in options.keys() else defaults[k]

    options['SESSION_EXPIRE']=int(eval(options['SESSION_EXPIRE']))

    return options

if __name__ == '__main__':
    logging.basicConfig(filename='lxcadmin.log')
#    logging.setLevel(options['LOGLEVEL'])
    logging.warn('LXC-Controller started')
    options = parse_config('/etc/lxcadmin/config.conf')
    app.config['SECRET_KEY']=options['SECRET_KEY']
    app.run(host=options['BIND'],port=int(options['PORT']))
