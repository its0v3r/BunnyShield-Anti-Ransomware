# IMPORTS
import json
import os
import subprocess


def setData():
    """Function to get data from the bs-config;json"""
    with open(GeneralConfig.PATH_TO_BUNNYSHIELD_CONFIG_JSON) as f:
        json_file_data = json.load(f)

        # General config
        GeneralConfig.HONEYFILE_JSON_ALIAS = json_file_data['general-config']['honeyfile-json-alias']
        GeneralConfig.HONEYFILE_NAMES_TXT_ALIAS = json_file_data['general-config']['honeyfile-txt-alias']

        # Audit config
        AuditConfig.FILE_EVENT_RULE_NAME = json_file_data['audit-config']['file-event-rule-name']
        AuditConfig.FILE_OPEN_SHELL_RULE_NAME = json_file_data['audit-config']['file-event-open-shell-name']

        # Honey config
        HoneyConfig.HONEY_ACTION = json_file_data['honey-config']['action']
        HoneyConfig.PATH_TO_HONEYFOLDER = json_file_data['honey-config']['path-to-honeyfolder']
        HoneyConfig.PATH_TO_WHITELISTED_FOLDER = json_file_data['honey-config']['path-to-whitelistedfolder']
        HoneyConfig.DIRECTORIES = json_file_data['honey-config']['directories']
        HoneyConfig.HONEYFILE_PREFIX = json_file_data['honey-config']['honeyfile-prefix']

        # File monitor
        FileMonitorConfig.SKIP_TO_MONITOR = json_file_data['file-monitor-config']['skip-to-monitor']


class GeneralConfig():
    """Class for general BunnyShield configuration"""
    PID = os.getpid()
    PPID = os.getppid()
    USER = os.environ['SUDO_USER']
    PATH_TO_BUNNYSHIELD = os.getcwd()
    PATH_TO_BUNNYSHIELD_CONFIG = os.path.join(PATH_TO_BUNNYSHIELD, "config")
    PATH_TO_BUNNYSHIELD_DATA = os.path.join(PATH_TO_BUNNYSHIELD, "data")
    PATH_TO_BUNNYSHIELD_UTILS = os.path.join(PATH_TO_BUNNYSHIELD, "utils")
    HONEYFILE_JSON_ALIAS = 'bs-honeyfiles.json'
    HONEYFILE_NAMES_TXT_ALIAS = 'bs-honeyfile-names.txt'
    PATH_TO_JSON_FILE = os.path.join(PATH_TO_BUNNYSHIELD_CONFIG, HONEYFILE_JSON_ALIAS)
    PATH_TO_TXT_FILE = os.path.join(PATH_TO_BUNNYSHIELD_CONFIG, HONEYFILE_NAMES_TXT_ALIAS)
    PATH_TO_BUNNYSHIELD_CONFIG_JSON = os.path.join(PATH_TO_BUNNYSHIELD_CONFIG, 'bs-config.json')
    FILE_EXT_LIST = [
        '.php', '.html', '.txt', '.htm', '.aspx', '.asp', '.js', '.css', '.pgsql.txt', '.mysql.txt', '.pdf', '.cgi', '.inc', '.gif', '.jpg', '.swf', '.xml', '.cfm', '.xhtml', '.wmv', '.zip', '.axd', '.gz', '.png', '.doc', '.shtml', '.jsp', '.ico', '.exe', '.csi', '.inc.php', '.config', '.jpeg',
        '.ashx', '.log', '.xls', '.0', '.old', '.mp3', '.com', '.tar', '.ini', '.asa', '.tgz', '.PDF', '.flv', '.php3', '.bak', '.rar', '.asmx', '.xlsx', '.page', '.phtml', '.dll', '.JPG', '.asax', '.1', '.msg', '.pl', '.GIF', '.ZIP', '.csv', '.css.aspx', '.2', '.JPEG', '.3', '.ppt', '.nsf', '.Pdf',
        '.Gif', '.bmp', '.sql', '.Jpeg', '.Jpg', '.xml.gz', '.Zip', '.new', '.avi', '.psd', '.rss', '.5', '.wav', '.action', '.db', '.dat', '.do', '.xsl', '.class', '.mdb', '.include', '.12', '.cs', '.class.php', '.htc', '.mov', '.tpl', '.4', '.6.12', '.9', '.js.php', '.mysql-connect', '.mpg',
        '.rdf', '.rtf', '.6', '.ascx', '.mvc', '.1.0', '.files', '.master', '.jar', '.vb', '.mp4', '.local.php', '.fla', '.require', '.de', '.docx', '.php5', '.wci', '.readme', '.7', '.cfg', '.aspx.cs', '.cfc', '.dwt', '.ru', '.LCK', '.Config', '.gif_var_DE', '.html_var_DE', '.net', '.ttf', '.HTM',
        '.X-AOM', '.jhtml', '.mpeg', '.ASP', '.LOG', '.X-FANCYCAT', '.php4', '.readme_var_DE', '.vcf', '.X-RMA', '.X-AFFILIATE', '.X-OFFERS', '.X-AFFILIATE_var_DE', '.X-AOM_var_DE', '.X-FANCYCAT_var_DE', '.X-FCOMP', '.X-FCOMP_var_DE', '.X-GIFTREG', '.X-GIFTREG_var_DE', '.X-MAGNIFIER',
        '.X-MAGNIFIER_var_DE', '.X-OFFERS_var_DE', '.X-PCONF', '.X-PCONF_var_DE', '.X-RMA_var_DE', '.X-SURVEY', '.tif', '.dir', '.json', '.6.9', '.Zif', '.wma', '.8', '.mid', '.rm', '.aspx.vb', '.tar.gz', '.woa', '.main', '.ram', '.opml', '.0.html', '.css.php', '.feed', '.lasso', '.6.3', '.shtm',
        '.sitemap', '.scc', '.tmp', '.backup', '.sln', '.org', '.conf', '.mysql-query', '.session-start', '.uk', '.10', '.14', '.TXT', '.orig', '.settings.php', '.19', '.cab', '.kml', '.lck', '.pps', '.require-once', '.asx', '.bok', '.msi', '.01', '.c', '.fcgi', '.fopen', '.html.', '.phpmailer.php',
        '.bin', '.htaccess', '.info', '.java', '.jsf', '.tmpl', '.0.2', '.00', '.6.19', '.DOC', '.bat', '.com.html', '.print', '.resx', '.ics', '.php.php', '.x', '.PNG', '.data', '.dcr', '.enfinity', '.html.html', '.licx', '.mno', '.plx', '.vm', '.11', '.5.php', '.50', '.HTML', '.MP3',
        '.config.php', '.dwg', '.edu', '.search', '.static', '.wws', '.6.edu', '.OLD', '.bz2', '.co.uk', '.ece', '.epc', '.getimagesize', '.ice', '.it_Backup_Giornaliero', '.it_Backup_Settimanale', '.jspa', '.lst', '.php-dist', '.svc', '.vbs', '.1.html', '.30-i486', '.ai', '.cur', '.dmg', '.img',
        '.inf', '.seam', '.smtp.php', '.1-bin-Linux-2.0.30-i486', '.1a', '.34', '.5.3', '.7z', '.ajax', '.cfm.cfm', '.chm', '.csp', '.edit', '.file', '.gif.php', '.m3u', '.psp', '.py', '.sh', '.test', '.zdat', '.04', '.2.2', '.4.0', '.admin', '.captcha.aspx', '.dev', '.eps', '.file-get-contents',
        '.fr', '.fsockopen', '.list', '.m4v', '.min.js', '.new.html', '.p', '.store', '.webinfo', '.xml.php', '.3.2', '.5.0', '.BAK', '.htm.', '.php.bak', '.1.1', '.1c', '.300', '.5.1', '.790', '.826', '.bk', '.bsp', '.cms', '.csshandler.ashx', '.d', '.html,', '.htmll', '.idx', '.images', '.jad',
        '.master.cs', '.prev_next', '.ssf', '.stm', '.txt.gz', '.00.8169', '.01.4511', '.112', '.134', '.156', '.2.0', '.21', '.24', '.4.9.php', '.4511', '.8169', '.969', '.Web.UI.WebResource.axd', '.as', '.asp.asp', '.au', '.cnf', '.dhtml', '.enu', '.html.old', '.include-once', '.lock', '.m',
        '.mysql-select-db', '.phps', '.pm', '.pptx', '.sav', '.sendtoafriendform', '.ssi', '.suo', '.vbproj', '.wml', '.xsd', '.025', '.075', '.077', '.083', '.13', '.16', '.206', '.211', '.246', '.26.13.391N35.50.38.816', '.26.24.165N35.50.24.134', '.26.56.247N35.52.03.605',
        '.27.02.940N35.49.56.075', '.27.15.919N35.52.04.300', '.27.29.262N35.47.15.083', '.367', '.3gp', '.40.00.573N35.42.57.445', '.403', '.43.58.040N35.38.35.826', '.44.04.344N35.38.35.077', '.44.08.714N35.39.08.499', '.44.10.892N35.38.49.246', '.44.27.243N35.41.29.367',
        '.44.29.976N35.37.51.790', '.44.32.445N35.36.10.206', '.44.34.800N35.38.08.156', '.44.37.128N35.40.54.403', '.44.40.556N35.40.53.025', '.44.45.013N35.38.36.211', '.44.46.104N35.38.22.970', '.44.48.130N35.38.25.969', '.44.52.162N35.38.50.456', '.44.58.315N35.38.53.455', '.445',
        '.45.01.562N35.38.38.778', '.45.04.359N35.38.39.112', '.45.06.789N35.38.22.556', '.45.10.717N35.38.41.989', '.455', '.456', '.499', '.556', '.605', '.778', '.816', '.970', '.989', '.ASPX', '.JS', '.PHP', '.array-keys', '.atom', '.award', '.bkp', '.crt', '.default', '.eml', '.epl',
        '.fancybox', '.fil', '.geo', '.h', '.hmtl', '.html.bak', '.ida', '.implode', '.index.php', '.iso', '.kmz', '.mysql-pconnect', '.php.old', '.php.txt', '.rec', '.storefront', '.taf', '.war', '.xslt', '.1.6', '.15', '.23', '.2a', '.8.1', '.CSS', '.NSF', '.Sponsors', '.a', '.aquery', '.ascx.cs',
        '.cat', '.contrib', '.ds', '.dwf', '.film', '.g', '.go', '.googlebook', '.gpx', '.hotelName', '.htm.htm', '.ihtml', '.in-array', '.index', '.ini.php', '.layer', '.maninfo', '.odt', '.price', '.randomhouse', '.read', '.ru-tov.html', '.s7', '.sample', '.sit', '.src', '.tpl.php', '.trck',
        '.uguide', '.vorteil', '.wbp', '.2.1', '.2.html', '.3.1', '.30', '.AVI', '.Asp', '.EXE', '.WMV', '.asax.vb', '.aspx.aspx', '.btr', '.cer', '.common.php', '.de.html', '.html\u200e', '.jbf', '.lbi', '.lib.php', '.lnk', '.login', '.login.php', '.mhtml', '.mpl', '.mso', '.mysql-result',
        '.original', '.pgp', '.ph', '.php.', '.preview', '.preview-content.php', '.search.htm', '.site', '.text', '.view', '.0.1', '.0.5', '.1.2', '.2.9', '.3.5', '.3.html', '.4.html', '.5.html', '.72', '.ICO', '.Web', '.XLS', '.action2', '.asc', '.asp.bak', '.aspx.resx', '.browse', '.code',
        '.com_Backup_Giornaliero', '.com_Backup_Settimanale', '.csproj', '.dtd', '.en.html', '.ep', '.eu', '.form', '.html1', '.inc.asp', '.index.html', '.it', '.nl', '.ogg', '.old.php', '.old2', '.opendir', '.out', '.pgt', '.php,', '.php\u200e', '.po', '.prt', '.query', '.rb', '.rhtml', '.ru.html',
        '.save', '.search.php', '.t', '.wsdl', '.0-to1.2.php', '.0.3', '.03', '.18', '.2.6', '.3.0', '.3.4', '.4.1', '.6.1', '.7.2', '.CFM', '.MOV', '.MPEG', '.Master', '.PPT', '.TTF', '.Templates', '.XML', '.adp', '.ajax.php', '.apsx', '.asf', '.bck', '.bu', '.calendar', '.captcha', '.cart',
        '.com.crt', '.core', '.dict.php', '.dot', '.egov', '.en.php', '.eot', '.errors', '.f4v', '.fr.html', '.git', '.ht', '.hta', '.html.LCK', '.html.printable', '.ini.sample', '.lib', '.lic', '.map', '.master.vb', '.mi', '.mkdir', '.o', '.p7b', '.pac', '.parse.errors', '.pd', '.pfx', '.php2',
        '.php_files', '.phtm', '.png.php', '.portal', '.printable', '.psql', '.pub', '.q', '.ra', '.reg', '.restrictor.php', '.rpm', '.strpos', '.tcl', '.template', '.tiff', '.tv', '.us', '.user', '.06', '.09', '.1.3', '.1.5.swf', '.2.3', '.25', '.3.3', '.4.2', '.6.5', '.Controls', '.WAV', '.acgi',
        '.alt', '.array-merge', '.back', '.call-user-func-array', '.cfml', '.cmd', '.cocomore.txt', '.detail', '.disabled', '.dist.php', '.djvu', '.dta', '.e', '.extract', '.file-put-contents', '.fpl', '.framework', '.fread', '.htm.LCK', '.inc.js', '.includes', '.jp', '.jpg.html', '.l', '.letter',
        '.local', '.num', '.pem', '.php.sample', '.php}', '.php~', '.pot', '.preg-match', '.process', '.ps', '.r', '.raw', '.rc', '.s', '.search.', '.server', '.sis', '.sql.gz', '.squery', '.subscribe', '.svg', '.svn', '.thtml', '.tpl.html', '.ua', '.vcs', '.xhtm', '.xml.asp', '.xpi', '.0.0',
        '.0.4', '.07', '.08', '.10.html', '.17', '.2008', '.2011', '.22', '.25.html', '.2ms2', '.3.2.min.js', '.32', '.33', '.4.6', '.5.6', '.6.0', '.7.1', '.91', '.A', '.PAGE', '.SWF', '.add', '.array-rand', '.asax.cs', '.asax.resx', '.ascx.vb', '.aspx,', '.aspx.', '.awm', '.b', '.bhtml', '.bml',
        '.ca', '.cache', '.cfg.php', '.cn', '.cz', '.de.txt', '.diff', '.email', '.en', '.error', '.faces', '.filesize', '.functions.php', '.hml', '.hqx', '.html,404', '.html.php', '.htmls', '.htx', '.i', '.idq', '.jpe', '.js.aspx', '.js.gz', '.jspf', '.load', '.media', '.mp2', '.mspx', '.mv',
        '.mysql', '.new.php', '.ocx', '.oui', '.outcontrol', '.pad', '.pages', '.pdb', '.pdf.', '.pnp', '.pop_formata_viewer', '.popup.php', '.popup.pop_formata_viewer', '.pvk', '.restrictor.log', '.results', '.run', '.scripts', '.sdb', '.ser', '.shop', '.sitemap.xml', '.smi', '.start', '.ste',
        '.swf.swf', '.templates', '.textsearch', '.torrent', '.unsubscribe', '.v', '.vbproj.webinfo', '.web', '.wmf', '.wpd', '.ws', '.xpml', '.y', '.0.8', '.0.pdf', '.001', '.1-all-languages', '.1.pdf', '.11.html', '.125', '.20', '.20.html', '.2007', '.26.html', '.4.7', '.45', '.5.4', '.6.2',
        '.6.html', '.7.0', '.7.3', '.7.html', '.75.html', '.8.2', '.8.3', '.AdCode', '.Aspx', '.C.', '.COM', '.GetMapImage', '.Html', '.Run.AdCode', '.Skins', '.Z', '.access.login', '.ajax.asp', '.app', '.asd', '.asm', '.assets', '.at', '.bad', '.bak2', '.blog', '.casino', '.cc', '.cdr',
        '.changeLang.php', '.children', '.com,', '.com-redirect', '.content', '.copy', '.count', '.cp', '.csproj.user', '.custom', '.dbf', '.deb', '.delete', '.details.php', '.dic', '.divx', '.download', '.download.php', '.downloadCirRequirements.pdf', '.downloadTourkitRequirements.pdf',
        '.emailCirRequirements.php', '.emailTourkitForm.php', '.emailTourkitNotification.php', '.emailTourkitRequirements.php', '.epub', '.err', '.es', '.exclude', '.filemtime', '.fillPurposes2.php', '.grp', '.home', '.htlm', '.htm,', '.html-', '.image', '.inc.html', '.it.html', '.j', '.jnlp',
        '.js.asp', '.js2', '.jspx', '.lang-en.php', '.link', '.listevents', '.log.0', '.mbox', '.mc_id', '.menu.php', '.mgi', '.mod', '.net.html', '.news', '.none', '.off', '.p3p', '.php.htm', '.php.static', '.php1', '.phpp', '.pop3.php', '.pop_3D_viewer', '.popup.pop_3D_viewer', '.prep', '.prg',
        '.print.html', '.print.php', '.product_details', '.pwd', '.pyc', '.red', '.registration', '.requirementsFeesTable.php', '.roshani-gunewardene.com', '.se', '.sea', '.sema', '.session', '.setup', '.simplexml-load-file', '.sitx', '.smil', '.srv', '.swi', '.swp', '.sxw', '.tar.bz2', '.tem',
        '.temp', '.template.php', '.top', '.txt.php', '.types', '.unlink', '.url', '.userLoginPopup.php', '.visaPopup.php', '.visaPopupValid.php', '.vspscc', '.vssscc', '.w', '.work', '.wvx', '.xspf', '.-', '.-110,-maria-lund-45906.-511-gl.php', '.-tillagg-order-85497.php', '.0-rc1', '.0.10',
        '.0.11', '.0.328.1.php', '.0.329.1.php', '.0.330.1.php', '.0.6', '.0.7', '.0.806.1.php', '.0.xml', '.0.zip', '.000', '.002', '.02', '.030-i486', '.05', '.07.html', '.1-3.2.php', '.1-bin-Linux-2.030-i486', '.1-pt_BR', '.1.5', '.1.8', '.1.htm', '.10.10', '.11.2010', '.12.html', '.13.html',
        '.131', '.132', '.15.html', '.16.html', '.2-rc1', '.2.5', '.2.8', '.2.js', '.2.pdf', '.2004', '.2006', '.2009', '.2010', '.21.html', '.23.html', '.26', '.27', '.27.html', '.29.html', '.31', '.35', '.4.2.min.js', '.4.4', '.45.html', '.5.1-pt_BR', '.5.2', '.5.7', '.5.7-pl1',
        '.6-all-languages', '.6.14', '.6.16', '.6.18', '.6.2-rc1', '.62.html', '.63.html', '.64', '.65', '.66', '.7-pl1', '.762', '.8.2.4', '.8.5', '.8.7', '.80.html', '.808', '.85', '.9.1', '.90', '.92', '.972', '.98.html', '.Admin', '.E.', '.Engineer', '.INC', '.LOG.new', '.MAXIMIZE', '.MPG',
        '.NDM', '.Php', '.R', '.SIM', '.SQL', '.Services', '.[file', '.accdb', '.act', '.actions.php', '.admin.php', '.ads', '.alhtm', '.all', '.ani', '.apf', '.apj', '.ar', '.aral-design.com', '.aral-design.de', '.arc', '.array-key-exists', '.asp.old', '.asp1', '.aspg', '.bfhtm', '.biminifinder',
        '.br', '.browser', '.build', '.buscar', '.categorias', '.categories', '.ccs', '.ch', '.cl', '.click.php', '.cls', '.cls.php', '.cms.ad.AdServer.cls', '.com-tov.html', '.com.ar', '.com.br', '.com.htm', '.com.old', '.common', '.conf.php', '.contact.php', '.control', '.core.php',
        '.counter.php', '.coverfinder', '.create.php', '.cs2', '.d2w', '.dbm', '.dct', '.dmb', '.doc.doc', '.dxf', '.ed', '.email.shtml', '.en.htm', '.engine', '.env', '.error-log', '.esp', '.ex', '.exc', '.exe,', '.ext', '.external', '.ficheros', '.fichiers', '.flush', '.fmt', '.fn', '.footer',
        '.form_jhtml', '.friend', '.g.', '.geo.xml', '.ghtml', '.google.com', '.gov', '.gpg', '.hl', '.href', '.htm.d', '.htm.html', '.htm.old', '.htm2', '.html.orig', '.html.sav', '.html[', '.html]', '.html_', '.html_files', '.htmlpar', '.htmlprint', '.html}', '.htm~', '.hts', '.hu', '.hwp',
        '.ibf', '.il', '.image.php', '.imagecreatetruecolor', '.imagejpeg', '.iml', '.imprimer', '.imprimer-cadre', '.imprimir', '.imprimir-marco', '.info.html', '.info.php', '.ini.bak', '.ini.default', '.inl', '.inv', '.join', '.jpg.jpg', '.jps', '.key', '.kit', '.lang', '.lignee', '.ltr', '.lzh',
        '.m4a', '.mail', '.manager', '.md5', '.met', '.metadesc', '.metakeys', '.mht', '.min', '.mld', '.mobi', '.mobile', '.mv4', '.n', '.net-tov.html', '.nfo', '.nikon', '.nodos', '.nxg', '.obyx', '.ods', '.old.2', '.old.asp', '.old.html', '.open', '.opml.config', '.ord', '.org.zip', '.ori',
        '.partfinder', '.pho', '.php-', '.phpl', '.phpx', '.pix', '.pls', '.prc', '.pre', '.prhtm', '.print-frame', '.print.', '.print.shtml', '.printer', '.properties', '.propfinder', '.pvx', '.p\u200bhp', '.recherche', '.redirect', '.req', '.roshani-gunewardene.net', '.roshani-m-gunewardene.com',
        '.safe', '.sbk', '.se.php', '.search.asp', '.sec', '.seo', '.serv', '.server.php', '.servlet', '.settings', '.sf', '.shopping_return.php', '.shopping_return_adsense.php', '.show', '.sht', '.skins', '.so', '.sph', '.split', '.sso', '.stats.php', '.story', '.swd', '.swf.html', '.sys', '.tex',
        '.tga', '.thm', '.tlp', '.tml', '.tmp.php', '.touch', '.tsv', '.txt.', '.txt.html', '.ug', '.unternehmen', '.utf8', '.vbproj.vspscc', '.vsprintf', '.vstemplate', '.vtl', '.wbmp', '.webc', '.webproj', '.wihtm', '.wp', '.wps', '.wri', '.wsc', '.www', '.xsp', '.xsql', '.zip,', '.zml', '.ztml',
        '. EXTRAHOTELERO HOSPEDAJE', '. T.', '. php', '.,', '.-0.html', '.-bouncing', '.-safety-fear', '.0--DUP.htm', '.0-0-0.html', '.0-2.html', '.0-4.html', '.0-features-print.htm', '.0-pl1', '.0-to-1.2.php', '.0.0.0', '.0.1.1', '.0.10.html', '.0.11-pr1', '.0.15', '.0.35', '.0.8.html', '.0.jpg',
        '.00.html', '.001.L.jpg', '.002.L.jpg', '.003.L.jpg', '.003.jpg', '.004.L.jpg', '.004.jpg', '.006', '.006.L.jpg', '.01-10', '.01-L.jpg', '.01.html', '.01.jpg', '.011', '.017', '.02.html', '.03.html', '.04.html', '.041', '.05.09', '.05.html', '.052', '.06.html', '.062007', '.070425',
        '.08-2009', '.08.2010.php', '.08.html', '.09.html', '.0b', '.1-en', '.1-english', '.1-rc1', '.1.0.html', '.1.10', '.1.2.1', '.1.24-print.htm', '.1.9498', '.1.php', '.1.x', '.10.1', '.10.11', '.10.2010', '.10.5', '.100.html', '.1008', '.105', '.1052', '.10a', '.11-pr1',
        '.11.5-all-languages-utf-8-only', '.11.6-all-languages', '.110607', '.1132', '.12.pdf', '.125.html', '.1274', '.12D6', '.12EA', '.133', '.139', '.13BA', '.13F8', '.14.05', '.14.html', '.1478', '.150.html', '.1514', '.15462.articlePk', '.15467.articlePk', '.15F4', '.160', '.161E', '.16BE',
        '.1726', '.175', '.17CC', '.18.html', '.180', '.1808', '.1810', '.1832', '.185', '.18A', '.19.html', '.191E', '.1958', '.1994', '.199C', '.1ADE', '.1C2E', '.1C50', '.1CD6', '.1D8C', '.1E0', '.1_stable', '.2-english', '.2.0.html', '.2.00', '.2.2.html', '.2.2.pack.js', '.2.6.min.js',
        '.2.6.pack.js', '.2.7', '.2.php', '.2.swf', '.2.tmp', '.2.zip', '.200.html', '.2004.html', '.2005', '.2009.pdf', '.202', '.205.html', '.20A6', '.22.html', '.220', '.24.html', '.246.224.125', '.24stable', '.25.04', '.25CE', '.2769', '.28.html', '.2808', '.29', '.2ABE', '.2B26', '.2CC',
        '.2CD0', '.2D1A', '.2DE', '.2E4', '.2E98', '.2EE2', '.2b', '.3-pl1', '.3-rc1', '.3.2a', '.3.6', '.3.7-english', '.3.asp', '.3.php', '.30.html', '.308E', '.31.html', '.330', '.3374', '.33E0', '.346A', '.347A', '.347C', '.3500', '.3590', '.35B8', '.36', '.37', '.37.0.html', '.37C2', '.3850',
        '.3EA', '.3F54', '.4-all-languages', '.4.10a', '.4.14', '.4.3', '.4.5', '.40.html', '.4040', '.414', '.41A2', '.4234', '.42BA', '.43', '.43CA', '.43FA', '.4522', '.4556', '.464', '.46A2', '.46D4', '.47F6', '.482623', '.4884', '.490', '.497C', '.4A4', '.4A84', '.4B88', '.4C6', '.4CC',
        '.4D3C', '.4D6C', '.4FB8', '.5-all-languages-utf-8-only', '.5-pl1', '.5.1.html', '.5.5-pl1', '.5.i', '.50.html', '.508', '.50A', '.51', '.5214', '.55.html', '.574', '.576', '.5B0', '.5E0', '.5E5E', '.5_mod_for_host', '.6.0-pl1', '.6.3-pl1', '.6.3-rc1', '.6.4', '.608', '.61.html', '.63',
        '.65.html', '.65E', '.67E', '.698', '.69A', '.6A0', '.6CE', '.6D2', '.6D6', '.6DA', '.6EE', '.6F8', '.6FA', '.6FC', '.7-2.html', '.7-english', '.7.2.custom', '.7.5', '.7.js', '.710', '.71E', '.71a', '.732', '.73C', '.776', '.77C', '.7878', '.78A', '.792', '.79C', '.7AB6', '.7AE', '.7AF8',
        '.7B0', '.7B30', '.7B5E', '.7C6', '.7C8', '.7CA', '.7CC', '.7D6', '.7E6', '.7F0', '.7F4', '.7FA', '.7FE', '.7_0_A', '.8.0', '.8.0.html', '.8.23', '.8.4', '.8.html', '.802', '.80A', '.80E', '.824', '.830', '.832', '.836', '.84', '.84.119.131', '.842', '.84CA', '.84E', '.854', '.856', '.858',
        '.860', '.862', '.866', '.878', '.87C', '.888luck.asia', '.88C', '.8990', '.89E', '.8AE', '.8B0', '.8C6', '.8D68', '.8DC', '.8E6', '.8EC', '.8EE', '.8a', '.9.2', '.9.6.2', '.9.html', '.90.3', '.90.html', '.918', '.924', '.94', '.9498', '.95', '.95.html', '.964', '.97C', '.984', '.99',
        '.99E', '.9A6', '.9C', '.9CEE', '.9D2', '.A.', '.A00', '.A02', '.A22', '.A34', '.A40', '.A4A', '.A50', '.A58', '.A5CA', '.A8A', '.AB60', '.AC0', '.AC2', '.ACA2', '.AE2', '.AEFA', '.AF54', '.AF90', '.ALT', '.ASC.', '.Acquisition', '.Appraisal', '.B04', '.B18', '.B1C', '.B2C', '.B38', '.B50',
        '.B5E', '.B70', '.B7A', '.B8A', '.BBC', '.BD0', '.BMP', '.C.R.D.', '.C38', '.C44', '.C50', '.C68', '.C72', '.C78', '.C7C', '.C84', '.CAA', '.CAB', '.CB8', '.CBC', '.CC0', '.CF4', '.CF6', '.CGI', '.Cfm', '.Commerce', '.CorelProject', '.Css', '.D.', '.D.R.', '.D20', '.D7A', '.DBF', '.DC2',
        '.DESC.', '.DLL', '.DOCX', '.Direct', '.DnnWebService', '.Doc', '.E46', '.E96', '.EA0', '.EBA', '.EC0', '.EDE', '.EEA', '.EF8', '.Email', '.Eus', '.F22', '.F46', '.F54', '.FAE', '.FRK', '.H.I.', '.INFO', '.INI', '.ISO', '.Includes', '.K.E.', '.K.T.', '.KB', '.L.', '.L.jpg', '.LassoApp',
        '.MLD', '.Main', '.NET', '.NEWCONFIGPOSSIBLYBROKEN', '.Old', '.Org.master', '.Org.master.cs', '.Org.sln', '.Org.vssscc', '.P.', '.PSD', '.Publish', '.RAW', '.S', '.SideMenu', '.Sol.BBCRedirection.page', '.Superindian.com', '.T.A', '.T.A.', '.TEST', '.Tung.php', '.WTC', '.XMLHTTP', '.Xml',
        '._._order', '._heder.yes.html', '._order', '.a.html', '.a5w', '.aac', '.access', '.act.php', '.action.php', '.actions', '.activate.php', '.ad.php', '.add.php', '.adenaw.com', '.adm', '.advsearch', '.ag.php', '.aj_', '.all.hawaii', '.amaphun.com', '.andriy.lviv.ua', '.ap', '.api', '.apk',
        '.application', '.archiv', '.arj', '.array-map', '.array-values', '.art', '.artdeco', '.articlePk', '.artnet.', '.ascx.resx', '.asia', '.asp-', '.asp.LCK', '.asp.html', '.asp2', '.aspDONOTUSE', '.asp_', '.asp_files', '.aspl', '.aspp', '.asps', '.aspx.designer.cs', '.aspx_files', '.aspxx',
        '.aspy', '.asxp', '.as\u200bp', '.at.html', '.avatar.php', '.awstats', '.a\u200bsp', '.babymhiasexy.com', '.backup.php', '.bak.php', '.banan.se', '.banner.php', '.barnes', '.basicmap.php', '.baut', '.bc', '.best-vpn.com', '.beta', '.biz', '.blackandmature.com', '.bmp.php', '.board.asd',
        '.boom', '.bossspy.org', '.buscadorpornoxxx.com', '.buy-here.com', '.buyadspace', '.bycategory', '.bylocation', '.bz', '.c.html', '.cache.inc.php', '.cache.php', '.car', '.cascinaamalia.it', '.cat.php', '.catalog', '.cdf', '.ce', '.cfm.bak', '.cfsifatest.co.uk', '.cfstest.co.uk', '.cfswf',
        '.cfx', '.cgis', '.chat', '.chdir', '.chloesworld.com', '.classes.php', '.cmp', '.cnt', '.co', '.co-operativebank.co.uk', '.co-operativebanktest.co.uk', '.co-operativeinsurance.co.uk', '.co-operativeinsurancetest.co.uk', '.co-operativeinvestmentstest.co.uk', '.co.il', '.colorbox-min.js',
        '.com-authorization-required.html', '.com-bad-request.html', '.com-forbidden.html', '.com-internal-server-error.html', '.com-page-not-found.html', '.com.au', '.com.php', '.com.ua', '.com_Backup_', '.com_files', '.comments', '.comments.', '.comments.php', '.compiler.php', '.conf.html',
        '.confirm.email', '.connect.php', '.console', '.contact', '.content.php', '.controller', '.controls-3.1.5.swf', '.cookie.js', '.corp', '.corp.footer', '.cqs', '.cron', '.cropcanvas.php', '.cropinterface.php', '.crx', '.csproj.webinfo', '.csr', '.css.LCK', '.css.gz', '.cssd', '.csv.php',
        '.ctp', '.cx', '.cycle.all.min.js', '.d64', '.daisy', '.dal', '.daniel', '.daniel-sebald.de', '.data.php', '.data_', '.davis', '.dbml', '.dcf', '.de.jsp', '.default.php', '.del', '.deleted', '.dell', '.demo', '.desarrollo.aquihaydominios.com', '.dev.bka.co.nz', '.development', '.dig',
        '.display.php', '.dist', '.dk', '.dm', '.dmca-sucks.com', '.dms', '.dnn', '.dogpl', '.donothiredandobrin.com', '.dontcopy', '.downloadfreeporn.asia', '.du', '.dump', '.dws', '.dyn', '.ea3ny.com', '.easing.min.js', '.ebay', '.ebay.results.html', '.editingoffice.com', '.efacil.com.br',
        '.ehtml', '.emaximinternational.com', '.en.jsp', '.enn', '.equonix.com', '.es.html', '.es.jsp', '.euforyou.net', '.eur', '.excel.xml.php', '.exec', '.exp', '.f.l.', '.faucetdepot', '.faucetdepot.com.vbproj', '.faucetdepot.com.vbproj.webinfo', '.fb2', '.fdml', '.feeds.php', '.ffa',
        '.ficken.cx', '.filereader', '.filters.php', '.flac', '.flypage', '.fon', '.forget.pass', '.form.php', '.forms', '.forum', '.found', '.fp7', '.fr.jsp', '.freeasianporn.asia', '.freepornxxx.asia', '.frk', '.frontpage.php', '.ft', '.ftl', '.fucks.nl', '.funzz.fr', '.gallery.php', '.garcia',
        '.gb', '.get', '.get-meta-tags', '.gif', '.gif.count', '.girlvandiesuburbs.co.za', '.gitihost.com', '.glasner.ru', '.google', '.gray', '.gsp', '.guiaweb.tk', '.gutschein', '.guy', '.ha', '.hardestlist.com', '.hardpussy.com', '.hasrett.de', '.hawaii', '.header.php', '.henry', '.him',
        '.history', '.hlr', '.hm', '.ho', '.hokkaido', '.hold', '.home.php', '.home.test', '.homepage', '.hp', '.htm.bak', '.htm.rc', '.htm3', '.htm5', '.htm7', '.htm8', '.htm_', '.html,,', '.html-0', '.html-1', '.html-c', '.html-old', '.html-p', '.html.htm', '.html.images', '.html.inc',
        '.html.none', '.html.pdf', '.html.start', '.html.txt', '.html4', '.html5', '.html7', '.htmlBAK', '.htmlDolmetschen', '.html_old', '.htmla', '.htmlc', '.htmlfeed', '.htmlq', '.htmlu', '.htn', '.htpasswd', '.h\u200btml', '.iac.', '.ibuysss.info', '.iconv', '.idf', '.iframe_filtros',
        '.ignore.php', '.ihmtl', '.ihya', '.imp', '.in', '.inactive', '.inc.php.bak', '.inc.php3', '.incest-porn.sex-startje.nl', '.incestporn.sex-startje.nl', '.incl', '.indiansexzite.com', '.indt', '.ini.NEWCONFIGPOSSIBLYBROKEN', '.insert', '.internet-taxprep.com', '.interpreterukraine.com',
        '.ipl', '.issues', '.itml', '.ixi', '.jhtm', '.job', '.joseph', '.jpf', '.jpg.xml', '.jpg[', '.jpg]', '.js,', '.js.LCK', '.jsa', '.jsd', '.jso', '.jsp.old', '.jsps', '.jtp', '.keyword', '.kinkywear.net', '.kk', '.knvbcommunicator.voetbalassist.nl', '.kokuken', '.ks', '.kutxa.net-en',
        '.lang-de.php', '.lang.php', '.langhampartners.com', '.lappgroup.com', '.last', '.latest', '.lha', '.links', '.list.includes', '.listMiniGrid', '.listing', '.lng', '.loc', '.local.cfm', '.location.href', '.log2', '.lua', '.lynkx', '.maastrichtairporthotels.com', '.mag', '.mail.php',
        '.malesextoys.us', '.massivewankers.com', '.mbizgroup', '.mel', '.members', '.meretrizdelujo.com', '.messagey.com', '.metadata.js', '.meus.php', '.midi', '.milliculture.net', '.min_', '.miss-video.com', '.mk.gutschein', '.mk.rabattlp', '.mkv', '.mmap', '.model-escorts.asia',
        '.modelescorts.asia', '.mp', '.mp3.html', '.mq4', '.mreply.rc', '.msp', '.mvn', '.mysqli', '.napravlenie_ASC', '.napravlenie_DESC', '.nded-pga-emial', '.net-en', '.net-print.htm', '.net_Backup_Giornaliero', '.net_Backup_Settimanale', '.new.htm', '.newsletter', '.nexucom.com',
        '.ninwinter.net', '.nl.html', '.nonude.org', '.nonudes.com', '.nth', '.nz', '.od', '.offer.php', '.offline', '.ogv', '.ok', '.old.1', '.old.htm', '.old.old', '.old1', '.old3', '.older', '.oliver', '.onedigitalcentral.com', '.onenettv.com', '.online', '.opensearch', '.org-tov.html',
        '.org.ua-tov.html', '.orig.html', '.origin.php', '.original.html', '.orlando-vacationhome.net', '.orlando-vacationhomes-pools.com', '.orlando-vacationrentals.net', '.osg', '.outbound', '.owen', '.ownhometest.co.uk', '.pae', '.page_pls_all_password', '.pages-medicales.com', '.pan',
        '.parse-url', '.part', '.pass', '.patch', '.paul', '.paymethods.php', '.pazderski.com', '.pazderski.net', '.pazderski.us', '.pdd', '.pdf.html', '.pdf.pdf', '.pdf.php', '.pdfx', '.perfect-color-world.com', '.petersburg-apartments-for-business.html', '.petersburg-apartments-for-tourists.html',
        '.petersburg-romantic-apartments.html', '.phdo', '.photo', '.php--------------', '.php.LCK', '.php.backup', '.php.html', '.php.inc', '.php.mno', '.php.original', '.php_', '.php_OLD', '.php_old', '.phphp', '.phppar', '.phpvreor.php', '.php', '.pht', '.pl.html', '.planetcom.ca',
        '.playwithparis.com', '.plugins', '.png,bmp', '.popup', '.pornfailures.com', '.pornoizlee.tk', '.pornz.tv', '.posting.prep', '.prev', '.print.jsp', '.prl', '.prosdo.com', '.psb', '.publisher.php', '.puresolo.com', '.pussyjourney.com', '.qtgp', '.qxd', '.r.', '.rabattlp', '.rails',
        '.randomocityproductions.com', '.rateart.php', '.readfile', '.rec.html', '.redirect.php', '.remove', '.remove.php', '.removed', '.resultados', '.resume', '.rhtm', '.riddlesintime.com', '.rmvb', '.ro', '.roma', '.roomscity.com', '.roshanigunewardene.com', '.rpt', '.rsp', '.rss.php',
        '.rss_cars', '.rss_homes', '.rss_jobs', '.rtfd', '.rvt', '.s.html', '.sadopasion.com', '.safariextz', '.salestax.php', '.sc', '.sca-tork.com', '.scandir', '.scrollTo.js', '.search.html', '.sec.cfm', '.section', '.secure', '.send', '.sent-', '.service', '.session-regenerate-id', '.set',
        '.sex-startje.nl', '.sexmeme.com', '.sexon.com', '.sexy-girls4abo.de', '.sfw', '.sgf', '.shipcode.php', '.shipdiscount.php', '.show.php', '.shtml.html', '.sidebar', '.sisx', '.sitemap.', '.skin', '.small-penis-humiliation.net', '.smiletest.co.uk', '.snippet.aspx', '.snuffx.com', '.sort',
        '.sortirovka_Price.napravlenie_ASC', '.sortirovka_Price.napravlenie_DESC', '.sortirovka_customers_rating.napravlenie_ASC', '.sortirovka_customers_rating.napravlenie_DESC', '.sortirovka_name.napravlenie_ASC', '.sortirovka_name.napravlenie_DESC', '.sp', '.sphp3', '.srch', '.srf', '.srvl',
        '.st-patricks.com', '.sta', '.staged.php', '.staging', '.start.php', '.stat', '.stats', '.step', '.stml', '.storebanner.php', '.storelogo.php', '.storename.php', '.sts.php', '.suarez', '.submit', '.support', '.support.html', '.swf.LCK', '.sym', '.system', '.tab-', '.table.html',
        '.tablesorter.min.js', '.tablesorter.pager.js', '.tatianyc.com', '.tb', '.tech', '.teen-shy.com', '.teenhardpussy.com', '.temp.php', '.templates.php', '.temporarily.withdrawn.html', '.test.cgi', '.test.php', '.tf', '.tg', '.thanks', '.thehotfish.com', '.theme', '.thompson', '.thumb.jpg',
        '.ticket.submit', '.tim', '.tk', '.tls', '.to', '.touch.action', '.trace', '.tracker.ashx', '.trade', '.trishasex.viedos.com', '.ts', '.tst', '.tvpi', '.txt.txt', '.txuri-urdin.com', '.ufo', '.ugmart.ug', '.ui-1.5.2', '.unixteacher.org', '.unsharp.php', '.update', '.upgrade', '.v1.11.js',
        '.v2.php', '.vacationhomes-pools.com', '.var', '.venetian.com,prod2.venetian.com,reservations.venetian.com,', '.verify', '.video', '.videodeputas.com', '.videos-chaudes.com', '.viewpage__10', '.vmdk', '.vn', '.voetbalassist.nl', '.vs', '.vx', '.vxlpub', '.w3m', '.w3x', '.wax',
        '.web-teck.com', '.webalizer', '.webarchive', '.webjockey.nl', '.webm', '.weedooz.eu', '.wgx', '.wimzi.php', '.wireless', '.wireless.action', '.wm', '.woolovers.com', '.working', '.wpl', '.wplus', '.wps.rtf', '.write.php', '.wwsec_app_priv.login', '.www.annuaire-vimarty.net',
        '.www.annuaire-web.info', '.www.kit-graphik.com', '.www.photo-scope.fr', '.xcam.at', '.xconf', '.xcwc.com', '.xgi', '.xhtml5', '.xlt', '.xm', '.xml.old', '.xpdf', '.xqy', '.xslx', '.xst', '.xsx', '.xy.php', '.yp', '.ys', '.z', '.za', '.zh.html', '.zhtml', '.zip.php', '.BNVMbP', '.FYFA3w',
        '.rwUCSz', '.vscdb-journal', '.LOCK']
    KEY_EXT_LIST = ['.key', '.keyfile', '.key-file', '.cryptkey', '.crypt-key', '.crypt-key-file', '.cryptkeyfile', '.crypto', '.cryptokey', '.crypto-key', '.crypto-key-file', '.cryptokeyfile', '.public-key',
                    '.publickey', '.private-key', '.privatekey', '.fernet-key', '.fernetkey', '.pem', '.csr', '.pkcs7', '.pkcs12', '.pfx', '.p12', '.der', '.cert', '.cer', '.crt', '.p7b', '.keystore', '.crl']
    PATH_TO_HOME_FOLDER = "/home"
    PATH_TO_ETC_FOLDER = "/etc"
    PATH_TO_HOME_DOTCONFIG = "/home/.config"


class AuditConfig():
    """Class for Audit configuration"""
    PATH_TO_AUDIT_CONF = subprocess.check_output(["find /etc audit/auditd.conf | grep audit/auditd.conf"], shell=True, stderr=subprocess.DEVNULL).decode()
    PATH_TO_AUDIT_DIR = os.path.join(PATH_TO_AUDIT_CONF.rsplit('/', 1)[0])
    PATH_TO_AUDIT_CUSTOM_RULES_FILE = os.path.join(PATH_TO_AUDIT_DIR, "rules.d", 'bunnyshield.rules')
    FILE_EVENT_RULE_NAME = "bs-file-event"
    FILE_OPEN_SHELL_RULE_NAME = "bs-open-shell-event"


class HoneyConfig():
    """Class for Honeyfiles configuration"""
    HONEY_ACTION = 'create'
    DISABLE_HONEYFILES = True
    PATH_TO_HONEYFOLDER = os.path.join("/home/matheusheidemann", 'testes')
    PATH_TO_WHITELISTED_FOLDER = os.path.join("/home/matheusheidemann", 'Decrypted Files Folder')
    RANDOM_WORDS = ['secret', 'bank', 'credit-card', 'data', 'password', 'finantial', 'money', 'personal', 'paypal', 'credentials']
    DIRECTORIES = [
        GeneralConfig.PATH_TO_HOME_FOLDER, GeneralConfig.PATH_TO_ETC_FOLDER
    ]
    HONEYFILE_PREFIX = ".0-secret-bsfile-"


class FileMonitorConfig():
    """Class for File Monitor configuration"""
    SKIP_TO_MONITOR = False
    EVENT_COUNT_TRIGGER = 50
    UNKNOW_EXTENSION_EVENT_COUNT_TRIGGER = 5
    HONEYFILE_MODIFIED_EVENT_COUNT_TRIGGER = 1
    HONEYFILE_DELETED_EVENT_COUNT_TRIGGER = 3
    FOLDER_WITH_HONEYFILES_DELETED_EVENT_COUNT_TRIGGER = 3
    CHECK_RANSOM_TIME = 5
    FILE_UPDATE_TIME = 15


class ProcessHandlerConfig():
    MAX_TAIL_FOR_DIR_CHANGES_EVENT = 10000
    MAX_TAIL_FOR_SHELL_OPEN_EVENT = 1000
    CHECK_IO_TIME = 1
    AMOUNT_OF_BYTES_TO_CHECK = 100000


class RegexConfig():
    """Class for Regex patterns"""
    ACTIVE_REG_PATTERN = "(?<=Active: )(.*?)(?=\ )"
    PATH_WITHOUT_FILE_PATTERN = "^.*/"
    FILE_IN_PATH_PATTERN = "([^\/]+$)"
    PID_PATTERN = "(?<=pid=)(.*?)(?=\ )"
    TTY_PATTERN = "(?<=tty=)(.*?)(?=\ )"
    COMM_PATTERN = '(?<=comm=")(.*?)(?=")'
    CWD_PATH_PATTERN = '(?<=cwd=).*'
    MALICIOUS_FILE_PATH_PATTERN = "(?<=.\\\)(.*)"


if __name__ == "__main__":
    pass
else:
    pass
