#Code to encrypt a file and upload on Dropbox
import dropbox
import os, random, struct
import Tkinter,tkFileDialog
import httplib2
import pprint
import mimeparse
import mimetypes
import shutil
import gnupg

from Tkinter import *
from apiclient.discovery import build
from apiclient.http import MediaFileUpload
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import flow_from_clientsecrets


# Get your app key and secret from the Dropbox developer website
app_key = ''
app_secret = ''

# Copy your credentials from the google console
CLIENT_ID = ''
CLIENT_SECRET = ''

OAUTH_SCOPE = 'https://www.googleapis.com/auth/drive'

# Redirect URI for installed apps
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'

#Dropbox account authentication 
flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)

client = dropbox.client.DropboxClient('')
#print 'linked account: ', client.account_info()

#Run through the OAuth flow and retrieve credentials
flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, OAUTH_SCOPE,
                           redirect_uri=REDIRECT_URI)
authorize_url = flow.step1_get_authorize_url()
print 'Go to the following link in your browser: ' + authorize_url
code = raw_input('Enter verification code: ').strip()
credentials = flow.step2_exchange(code)

# Create an httplib2.Http object and authorize it with our credentials
http = httplib2.Http()
http = credentials.authorize(http)

drive_service = build('drive', 'v2', http=http)

print 'Select and option:'

class App:
###The GUI code###
  def __init__(self, master):
    self.dvar = IntVar()
    self.gvar = IntVar()
    frame = Frame(master)
    frame.pack()
    frame = LabelFrame(master, text="Select an option", padx=5, pady=5)
    frame.pack(padx=10, pady=10)
    '''self.rb1 = Radiobutton(master, text="Dropbox", variable=self.dvar, value=1, command=self.dropencrypt_file)
    self.rb1.pack(side=LEFT)
    self.rb2 = Radiobutton(master, text="Gdrive", variable=self.gvar, value=2, command=self.gdrivencrypt_file)
    self.rb2.pack(side=LEFT)'''
    self.slogan = Button(frame,
                         text="Upload to Dropbox",
                         command=self.dropencrypt_file)
    self.slogan.pack(side=LEFT)
    self.slogan = Button(frame,
                         text="Upload to Gdrive",
                         command=self.dropencrypt_file)
    self.slogan.pack(side=LEFT)
    self.slogan = Button(frame,
                         text="Decrypt & download",
                         command=self.decrypt_file)
    self.slogan.pack(side=LEFT)
    self.button = Button(frame, 
                         text="QUIT", fg="red",
                         command=frame.quit)
    self.button.pack(side=LEFT)

###Dropbox Encryption code###

  def dropencrypt_file(self):
    gpg = gnupg.GPG()
    myFormats = [
    ('Text file','*.txt'),('PDF files','*.pdf'),('Microsoft word','*.doc'),('JPEG files','*.jpg')
    ]
    #if not out_filename:
    Tkinter.Tk().withdraw() # Close the root window
    in_filename = tkFileDialog.askopenfilename(title='Please select a file to encrypt',parent=root,filetypes=myFormats)
    in_name = os.path.basename(in_filename)
    out_filename = in_name[:-4]
    sign_name = out_filename+'_signfile'
    out_filename = out_filename+'_encrypted'+in_name[-4:]
    print 'out_filename'
    print out_filename
    filesize = os.path.getsize(in_filename)
   
    
    #open(in_filename, 'w').write('This is a cloud project at UTA')
    ###Digital signature###
    with open(in_filename, 'rb') as f:
       pass_phrase = raw_input("Please enter a passphrase for the Digital Signature:")
       signed_data = gpg.sign_file(f,passphrase='hithesh',detach=True)
       f.close()
    with open(sign_name, 'wb') as f:
       f.write(str(signed_data))    
       f.close() 
    ###GNUPG file encryption###
    with open(in_filename, 'rb') as f:
            status = gpg.encrypt_file(
            f, recipients = ['djhitze@gmail.com'],
            output = out_filename)
            print 'ok: ', status.ok
            print 'status: ', status.status
            print 'stderr: ', status.stderr
                
            ###Dropbox file upload###
            f = open(out_filename, 'rb')
            response = client.put_file(out_filename, f)
            f = open(sign_name, 'rb')
            response = client.put_file(sign_name, f)
 
            print out_filename + ' -- > Encrypted & signed -- > uploaded to Dropbox!' 


###Gdrive Encryption code###

  def gdrivencrypt_file(self):
    gpg = gnupg.GPG()
    myFormats = [
    ('Text file','*.txt'),('PDF files','*.pdf'),('Microsoft word','*.doc'),('JPEG files','*.jpg')
    ]
    #if not out_filename:
    Tkinter.Tk().withdraw() # Close the root window
    in_filename = tkFileDialog.askopenfilename(title='Please select a file to encrypt',parent=root,filetypes=myFormats)
    in_name = os.path.basename(in_filename)
    out_filename = in_name[:-4]
    sign_name = out_filename+'_signfile'
    out_filename = out_filename+'_encrypted'+in_name[-4:]
    print 'out_filename'
    print out_filename
    filesize = os.path.getsize(in_filename)
   
    
    #open(in_filename, 'w').write('This is a cloud project at UTA')
    ###Digital signature###
    with open(in_filename, 'rb') as f:
       pass_phrase = raw_input("Please enter a passphrase for the Digital Signature:")
       signed_data = gpg.sign_file(f,passphrase='hithesh',detach=True)
       f.close()
    with open(sign_name, 'wb') as f:
       f.write(str(signed_data))    
       f.close() 
    ###GNUPG file encryption###
    with open(in_filename, 'rb') as f:
            status = gpg.encrypt_file(
            f, recipients = ['djhitze@gmail.com'],
            output = out_filename)
            print 'ok: ', status.ok
            print 'status: ', status.status
            print 'stderr: ', status.stderr
                
            ###Google file upload###
            (mime_type, encoding) = mimetypes.guess_type(out_filename)
            media_body = MediaFileUpload(out_filename, mimetype=mime_type, resumable=False)
            body = {
            'title': out_filename,
            'description': 'A Filerazor encrypted file',
            'mimeType': 'Encrypted'
            }
            file = drive_service.files().insert(body=body, media_body=media_body).execute()
 
            print out_filename + ' -- > Encrypted & signed -- > uploaded to Gdrive!' 

###Decryption code###

  def decrypt_file(self):
    gpg = gnupg.GPG()
    in_name_enc = None
    in_name = None
    in_filename = tkFileDialog.askopenfilename(title='Please select a file to decrypt')
    in_name = os.path.basename(in_filename)
    in_name_enc = in_name
    in_name_len = len(in_name)
    in_name_len = in_name_len - 14
    fileName, file_extention = os.path.splitext(in_filename)
    filename_decrypted = in_name[:in_name_len] + file_extention
    out_filename = filename_decrypted
    sign_name = out_filename[:-4] + '_signfile'
    if len(in_filename) > 3:
       pass_phrase = raw_input("Please enter a passphrase for the Decryption:")
    ###End of passphrase GUI###
    
    ###GNUPG file Decryption###
    with open(in_filename, 'rb') as f:
       #status = gpg.decrypt_file(f,passphrase='hithesh',output=out_filename)
       status = gpg.decrypt_file(f,passphrase=pass_phrase,output=out_filename)
       f.close()
       print 'ok: ', status.ok
       print 'status: ', status.status
       print 'stderr: ', status.stderr
    with open(sign_name, 'rb') as f:
       verified=gpg.verify_file(f,out_filename)
       f.close()
       print "Digital signature verified succesfully" if verified else "Digital signature verification failed!"
       print out_filename + 'File decrypted and downloaded to local folder'	

root = Tk()
root.title("Dropbox file encryptor")
app = App(root)
root.mainloop()
        
     
