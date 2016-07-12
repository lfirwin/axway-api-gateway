# Deploy Script
# ---------------------------------

# ./run.sh kaiser/deployAPI.py --from 70x_wppdev1.fed --to HINT2_API --deploy
# ./run.sh kaiser/deployAPI.py --from HINT1_API --to HINT2_API --save --deploy

# Imports
from __future__ import with_statement
import ConfigParser, getpass, os, sys
from com.vordel.archive.fed import DeploymentArchive, PolicyArchive, EnvironmentArchive, Archive
from com.vordel.es.xes import PortableESPKFactory, PortableESPK
from com.vordel.es import Value
from com.vordel.env import EnvironmentSettings
from archiveutil import DeploymentArchiveAPI
from nmdeployment import NodeManagerDeployAPI
from optparse import OptionParser
import subprocess
from topologyapi import TopologyAPI
from kpsadmin import KPSAdmin
from kpsstore import StoreOperation
from com.vordel.kps.json import NodeConfigS
from com.vordel.kps.impl import Validator
from com.vordel.kps.client import KPSAdminClient
from com.vordel.kps.client import KPSClient
import configutil

# Classes
class Endpoint:

    def __init__(self, instanceId, topology, verbose=False, username="admin", password="changeme"):
        self.instanceId = instanceId
        self.verbose = verbose
        self.username = username
        self.password = password
        (self.adminScheme, self.adminHostname, self.adminPort) = configutil.getAdminNodeManagerSchemeHostPortFromTopology(topology)

    def getClient(self):
        url = self.getKPSApiServerUrl("kps")
        result = KPSClient(self.getConnectionContext(url))
        if self.verbose:
            result.setDebug(True)
        return result

    def getAdminClient(self):
        url = self.getKPSApiServerUrl("kpsadmin")
        result = KPSAdminClient(self.getConnectionContext(url))
        if self.verbose:
            result.setDebug(True)
        return result

    def getConnectionContext(self, url):
        return KPSClient.createConnectionContext(url, self.username, self.password)

    def getKPSApiServerUrl(self, servicePath):
        return "%s://%s:%s/api/router/service/%s/api/%s" % (self.adminScheme, self.adminHostname, self.adminPort, self.instanceId, servicePath)

    def getAdminConnectionDetails(self):
        branding = configutil.branding
        
        if self.adminScheme is not None:
            return "%s: %s://%s:%s" % (branding["admin.node.manager.display.name"], self.adminScheme, self.adminHostname, self.adminPort)
        else:
            print "Run managedomin to set %s connection details." % branding["admin.node.manager.display.name"]
            sys.exit(0)


class MyOptionParser(OptionParser):
    def error(self, msg): # ignore unknown arguments
        pass

# Functions
def deploy(adminNM, group, archive):
   results = adminNM.deployToGroup(group, archive)    
   for result in results:
      print
      print result.getArchiveId()
      failurecount = result.getErrorCount()
      if not result.getStatus():
         print "%i failures have occurred. " % failurecount
         print "Failed to deploy: Reason: "+ result.getFailureReason()
      else:
         if failurecount > 0:
            if failurecount == 1: 
               errString = "issue"
            else:
               errString = "issues"
            print "The deployment succeeded but %i %s recorded. " % (result.getErrorCount(), errString)
            for traceRecord in result.getTraceData().getTraceRecords():
               if traceRecord.getLevel() <= 2:
                  print traceRecord.getMessage()


def findEnvEntity(environmentalizedEntities, name):
   for envEntity in environmentalizedEntities:
     if envEntity.getKeyDescription() == name:
        return envEntity
   return None


def checkBasicProfile(es):
   envSettings = EnvironmentSettings(es.es)
   environmentalizedEntities = envSettings.getEnvSettings().getEnvironmentalizedEntities()
   
   basicProfiles = es.getAll('/[AuthProfilesGroup]name=Auth Profiles/[BasicAuthGroup]name=HTTP Basic/[BasicProfile]');
   for basicProfile in basicProfiles:
      entityPK = envSettings.findEnvironmentalizedEntity(basicProfile)
      if not entityPK:
         print basicProfile.getKeyDescription() + " not environmentalized!"
         continue
      
      if basicProfile.getEncryptedValue('httpAuthPass', 0):
         #print "Entity '%s' has httpAuthPass" % (basicProfile.getKeyDescription())
         envHttpAuthPass = False

         for envField in findEnvEntity(environmentalizedEntities, basicProfile.getKeyDescription()).getEnvironmentalizedFields():
            if envField.getEntityFieldName() == 'httpAuthPass':
               #print "Environmentalized Entity '%s' has httpAuthPass" % (envEntity.getKeyDescription())
               envHttpAuthPass = True
               break
         if envHttpAuthPass:
            continue
         else:
            print "WARNING: The Password value is not environmentalized for '%s'" % (envEntity.getKeyDescription())
            print "         Deployment will use the policy file as is and proceed."
            print "         Report this to development immediately for remediation."
            print


def updateEnvSettings(envSettingsDict, deploymentArchiveAPI):
   print;print "Updating Target Environment Package..."      
   for pk in envSettingsDict.keys():
      envSettingsForEntityListofLists = envSettingsDict[pk]
      entityToEnvironmentalize = deploymentArchiveAPI.entityStoreAPI.get(pk)
      for envSettingsForEntityList in envSettingsForEntityListofLists:
         fieldName = envSettingsForEntityList[0]
         index = int(envSettingsForEntityList[1])
         envSettingValue = envSettingsForEntityList[2]
         print "   Add env setting for pk '%s' field %s[%i]=%s" % (pk, fieldName, index, envSettingValue)
         envFieldEntity = deploymentArchiveAPI.envSettings.addEnviromentSetting(entityToEnvironmentalize, fieldName, index)
         if str(envFieldEntity.getType()) == "EnvironmentalizedFieldEncrypted":
            envSettingValue = str(deploymentArchiveAPI.entityStoreAPI.decrypt(envSettingValue))
         if str(envFieldEntity.getType()) == "EnvironmentalizedFieldInteger":
            envSettingValue = int(envSettingValue)
         if str(envFieldEntity.getType()) == "EnvironmentalizedFieldBoolean":
            if str(envSettingValue) == "false":
               envSettingValue = str(0)
            else:
               envSettingValue = str(1)
         if type(envSettingValue) is str:
            deploymentArchiveAPI.envSettings.setEnvironmentSettingValueAsString(envFieldEntity, envSettingValue)
         else:
            #The following check and set methods are added to environmentalize Reference type fields like Certs
            if deploymentArchiveAPI.envSettings.isReferenceField(entityToEnvironmentalize, envFieldEntity):
               referenceType = deploymentArchiveAPI.envSettings.getReferenceType(entityToEnvironmentalize, envFieldEntity)
               if (referenceType == 'Certificate'):
                  if fieldName == "caCerts":
                     envFieldEntity.setField("selectorType",[Value("true")])
                     envFieldEntity.setField("selectorAttributeType",[Value("com.vordel.client.manager.attr.CertTreeAttribute")])
                     envFieldEntity.setField("selectorSearch",[Value("false")])
                     envFieldEntity.setField("displayName",[Value("Signer Certificate(s)")])
                  elif fieldName == "sslUsers" or fieldName == "serverCert":
                     envFieldEntity.setField("selectorType",[Value("false")])
                     envFieldEntity.setField("selectorAttributeType",[Value("com.vordel.client.manager.attr.CertTreeAttribute")])
                     envFieldEntity.setField("selectorSearch",[Value("true")])
                     envFieldEntity.setField("displayName",[Value("Sever Certificate (optional)")])
               elif (referenceType == 'DbConnection'):
                  envFieldEntity.setField("selectorType",[Value("DbConnection")])
                  envFieldEntity.setField("selectorAttributeType",[Value("com.vordel.client.manager.attr.ESPKReferenceSummaryAttribute")])
                  envFieldEntity.setField("selectorSearch",[Value("DbConnectionGroup")])
               envSettingValue = PortableESPKFactory.newInstance().createPortableESPK(envSettingValue)
            deploymentArchiveAPI.envSettings.setEnvironmentSettingValue(envFieldEntity, envSettingValue)
         deploymentArchiveAPI.entityStoreAPI.updateEntity(envFieldEntity)

   # Update the federated entity store in the archive as have updated some env settings in EnvSettingsStore.xml
   deploymentArchiveAPI.deploymentArchive.updateConfiguration(deploymentArchiveAPI.entityStore)
   print "   Target Environment Package updated."      


def getSHK(pk):
   keys = pk[1:-1].split('><')
   shk = ""
   for key in keys:
      if key.startswith('key'):
         shk = shk + '/[' + key[:-1].split("='")[1] + ']'
      elif key.startswith('id'):
         shk = shk + 'name=' + key[:-2].split("value='")[1]
   shk = shk.replace("&apos;", "'")
   return shk


def displayEnvEntities(environmentalizedEntities, envEntityStore=None):
   for envEntity in environmentalizedEntities.getEnvironmentalizedEntities():
      fields = envEntity.getEnvironmentalizedFields()
      print "Entity '%s' of type '%s' has environmentalized fields:" % (envEntity.getKeyDescription(), envEntity.getType())
      for envField in fields:
         print "    %s[%i]=%s" % (envField.getEntityFieldName(), envField.getIndex(), envField.getValue())
      print


def getEnvSettingsDict(envEntities):
   envDict = {}
   for envEntity in envEntities.getEnvironmentalizedEntities():
      itemKey = getSHK(envEntity.getEntityPk())
      envDict[itemKey] = []
      envDict[itemKey].append(iniSection(getSHK(envEntity.getEntityPk())))
      envFields = {}
      for envField in envEntity.getEnvironmentalizedFields():
         fieldName = "%s[%i]" % (envField.getEntityFieldName(), envField.getIndex())
         envFields[fieldName] =  envField.getValue()
      envDict[itemKey].append(envFields)
   return envDict


def buildField(field, value):
   envField = []
   envField.append(field.split('[')[0])
   envField.append(int(field.split('[')[1].split(']')[0]))
   envField.append(value)
   return envField


def findField(searchList, field):
   fieldName = field.split('[')[0]
   fieldIndex = int(field.split('[')[1].split(']')[0])
   searchIndex = -1
   for envField in searchList:
      if envField[0] == fieldName and envField[1] == fieldIndex:
         searchIndex = searchList.index(envField)
         break
   return searchIndex

def compareEnvEntities(fromEnvEntities, toEnvEntities, toIni, promotedEnvEntities):
   print;print "Comparing Source to Target environmentalized entities..."
   valid = True
   for fromEnvEntity in fromEnvEntities:
      promotedEnvEntities[fromEnvEntity] = []
      fromFields = fromEnvEntities[fromEnvEntity][1]
      if fromEnvEntity in toEnvEntities: # from in target but not in INI
#         fromFields = fromEnvEntities[fromEnvEntity][1]
         toFields = toEnvEntities[fromEnvEntity][1]
         for fromField in fromFields:
            print fromField
            if str(fromFields[fromField]) == '-1' and str(toFields[fromField])  == '-1':
               print "no value set for field in source or target environment packages"
               valid = False
            elif str(fromFields[fromField]) == '-1':
               print "no value set for field in source environment package"
            elif not toFields.get(fromField, None):
               print "promoting source field to target environment package - no field in target"
               promotedEnvEntities[fromEnvEntity].append(buildField(fromField, fromFields[fromField]))
            elif fromFields[fromField] != toFields[fromField]:
               print "promoting source field to target environment pacakge - fields are different"
               promotedEnvEntities[fromEnvEntity].append(buildField(fromField, fromFields[fromField]))
#            if toFields.get(fromField, None):
#               del toFields[fromField]
      else:  # from not in target and not in INI
         print fromEnvEntity + " not in toEnvEntities"
#         fromFields = fromEnvEntities[fromEnvEntity][1]
         for fromField in fromFields:
            promotedEnvEntities[fromEnvEntity].append(buildField(fromField, fromFields[fromField]))
         print

      #Check for customized values for entity in target INI
      iniFields = None
      try:
         iniFields = toIni.items(fromEnvEntities[fromEnvEntity][0])
      except ConfigParser.NoSectionError:
         pass

      if iniFields:  # from in INI
         for iniField in iniFields:
            iniFieldValue = iniField[1].replace('>>>>', '\r\n')
            index = findField(promotedEnvEntities[fromEnvEntity], iniField[0])
            if index == -1:
               promotedEnvEntities[fromEnvEntity].append(buildField(iniField[0], iniFieldValue))
            else:
               promotedEnvEntities[fromEnvEntity][index] = buildField(iniField[0], iniFieldValue)

      # Delete update entity since it will not be promoted 
      if len(promotedEnvEntities[fromEnvEntity]) == 0:
         del promotedEnvEntities[fromEnvEntity]
         
      # Delete to entity if all fields will not be changed
      if fromEnvEntity in toEnvEntities and len(toEnvEntities[fromEnvEntity][1]) == 0:
         del toEnvEntities[fromEnvEntity]
         
   # Display entities to be deleted from target
   print
   print "Entities that are deleted:"
   print toEnvEntities

   # Display entities to be promoted
   print
   print "Entities to promote:"
   print promotedEnvEntities

   # Return valid updates
   print "  Compare comoplete."
   return valid


def iniSection(shk):
   names = shk.split("/")
   entityType = names[-1].split("name=")[0][1:-1]
   section = entityType + ":::" + names[-1].split("name=")[1]
   if entityType in "ConnectToURLFilter,ConnectionFilter,JavaScriptFilter": 
      section = names[-2].split("name=")[0][1:-1] + ":::" + names[-2].split("name=")[1] + ":::" + section
   return section


def buildIni(environmentalizedEntities, ini, ignoreTypes):
   print;print "Building Target INI..."
   if ignoreTypes == 'none':
      ignoreTypes = None
   elif ignoreTypes == '':
#      ignoreTypes = 'ConnectToURLFilter,ConnectionFilter,BasicProfile,JavaScriptFilter'
      ignoreTypes = 'ConnectToURLFilter,ConnectionFilter,BasicProfile'

   # Clean up ignored Sections
   if ignoreTypes:
      print "   Ignoring Entity Types: " + ignoreTypes
      sections = sorted(ini.sections())
      ignores = ignoreTypes.split(',')
      for section in sections:
         for ignore in ignores:
            if ignore in section:
               ini.remove_section(section)  
   else:
      print "   Adding all environmentalized entities to INI file"

   for envEntity in environmentalizedEntities.getEnvironmentalizedEntities():
      if ignoreTypes and envEntity.getType() in ignoreTypes:
         continue

      section = iniSection(getSHK(envEntity.getEntityPk()))
      if not ini.has_section(section):
         ini.add_section(section)

      fields = envEntity.getEnvironmentalizedFields()
      for envField in fields:
         ini.set(section, "%s[%i]" % (envField.getEntityFieldName(), envField.getIndex()), envField.getValue())

   print "   INI built."
   return ini


def writeIni(ini, inifile):
   print;print "Writing Target INI..."
   f = open(inifile, 'w')
   f.truncate()
   f.write("[Locations]\n")
   for item in ini.items("Locations"):
      f.write("%s = %s\n" % (item[0], item[1]))
   f.write("\n")
   sections = sorted(ini.sections())
   for section in sections:
      if section != "Locations":
         f.write("[%s]\n" % section)
         for item in ini.items(section):
            if item[1]:
               value = item[1].replace('\r\n', '>>>>')
               value = value.replace('\n', '>>>>')
            else:
               value = ''
            f.write("%s = %s\n" % (item[0], value))
         f.write("\n")
   f.close()
   print "   Target INI written to " + inifile


def getIniFile(scriptDir, envName):
   # Get the environment
   parts = envName.split("_")
   lowerEnvName = ""
   for part in parts:
      if part == "API":
         break
      if lowerEnvName == "":
         lowerEnvName = part.lower()
      else:
         lowerEnvName = lowerEnvName + "-" + part.lower()
   iniFile = "%s/environments/%s/%s.ini" % (scriptDir, lowerEnvName, envName)
   envDir = "%s/environments/%s/" % (scriptDir, lowerEnvName)
   return iniFile, envDir, lowerEnvName


def importConfigs(es, importsDir):
   print;print "Importing custom Target certs & policies..."
   for configFile in os.listdir(importsDir):
       if configFile.endswith(".xml"):
          configXml = os.path.join(importsDir, configFile)
          es.importConf(configXml)
          print "   Successfully imported: %s " %(configXml)
   return es


def updateKPS(nmURL, nmUserId, nmPassword, kpsSource, ini):
   if not os.path.isdir(kpsSource):
      print 'The KPS JSON source directory ' + kpsSource + ' does not exist'
      return
   groupName = ini.get('Locations', 'group')
   instanceName = ini.get('Locations', 'server')
   primaryHost = ini.get('Locations', 'node1')
   topologyAPI = TopologyAPI.create(nmURL, nmUserId, nmPassword)
   instance = topologyAPI.getServiceByName(groupName, instanceName).getId()
   if copyKPSJSON(kpsSource, '/apps/Axway-7.4/apigateway/instances/' + groupName + '/conf/kps/backup', primaryHost):
      restoreKPS(instance, nmUserId, nmPassword, topologyAPI.getTopology())
      deleteKPSJSON('/apps/Axway-7.4/apigateway/instances/' + groupName + '/conf/kps/backup', primaryHost)


def restoreKPS(instance, nmUserId, nmPassword, topology):
   #kpsadmin = KPSAdmin(verbose=True,username=nmUserId, password=nmPassword)
   kpsadmin = KPSAdmin(username=nmUserId, password=nmPassword)
   client = Endpoint(instance, topology, username=nmUserId, password=nmPassword).getClient()
   adminClient = Endpoint(instance, topology, username=nmUserId, password=nmPassword).getAdminClient()
   model = client.getModel()
   stores = model.stores
   uniquePackages = set()
   for store in stores:
      uniquePackages.add(store.config.get("package"))
   packages = list(uniquePackages)
   kpPackage = None
   for package in packages:
      if package == "Consumer_Authorization":
         print "Package: %s" %(package)
         kpPackage = package

   kpsadmin.model = model
   kpsadmin.package = kpPackage
   for s in kpsadmin.getStoresInPackage():
      print "Store alias: %s" %(s.alias)
      op = StoreOperation(adminClient, s, False)
      op.clear(False)
      uuid = ""
      safeid = Validator.createSafeId("%s_%s.json" % (uuid, s.identity))
      print "Safeid: %s" %(safeid)
      op.restore(safeid)

 
def copyKPSJSON(kpsSource, kpsBackupLocation, primaryHost):
   if os.system('scp ' + kpsSource + '/*json wasadm@' + primaryHost + ':' + kpsBackupLocation) == 0:
      return True
   else:
      return False


def deleteKPSJSON(kpsBackupLocation, primaryHost):
   if os.system('ssh wasadm@' + primaryHost + ' "rm -f ' + kpsBackupLocation + '/*json"') == 0:
      return True
   else:
      return False


def exportAPICJSON(apicInput, kpsDir, debug):
   # Export APIC Data
   apicExportArgs = "apicExport.py --input " + apicInput + " -j " + kpsDir
   if debug:
      apicExportArgs += " --debug"
   execCommand('python', apicExportArgs)
   
   
def copyJars(jarsDir, ini):
   index = 1
   while True:
      if ini.has_option('Locations', 'node' + str(index)):
         host = ini.get('Locations', 'node' + str(index))
         execCommand('rsync', '-a ' + jarsDir + ' wasadm@' + host + ':/apps/Axway-7.4/apigateway/ext/lib')
         index += 1
      else:
         break
     
     
def execCommand(command, args):
   cmd = []
   arguments = args.split()
   cmd.append(command)
   for arg in arguments:
      cmd.append(arg)
   try:
      result = subprocess.check_call(cmd)
   except subprocess.CalledProcessError, e:
      print "Execution failed:", e
      return False
   print "The command completed successfully: %s %s" % (command, args)
   return True


def buildDirectories(scriptDir):
   print "Composing required directories..."
   fedDir = scriptDir + "/FEDS/"
   backupDir = scriptDir + "/BACKUPS/"
   svnDir = scriptDir + "/SVN/"
   jarsDir = scriptDir + "/JARS/"
   kpsDir = scriptDir + "/KPS/"
   apicExport = '/'.join(scriptDir.split('/')[:-2]) + '/apic-export/'
   
   print "   Saved Deployment Packages: " + fedDir
   print "   Deployment Package Backups: " + backupDir
   print "   SVN: " + svnDir
   print "   JAR Files: " + jarsDir
   print "   KPS JSON Files: " + kpsDir
   print "   APIC Export Input: " + apicExport
   return scriptDir, fedDir, backupDir, svnDir, jarsDir, kpsDir, apicExport


def parseOptions(copyargs):
   print;print "Parsing options..."
   parser = MyOptionParser()
   parser.add_option("-f", "--from", dest="fromSource", help="Promoting from - URL or file name")
   parser.add_option("-t", "--to", dest="toTarget", help="Promoting to - URL or file name")
   parser.add_option("-d", "--deploy", action="store_true", dest="deploy", help="Deploy updates to group", default=False)
   parser.add_option("-s", "--save", action="store_true", dest="save", help="Save the target fed file", default=False)
   parser.add_option("-m", "--month", dest="month", help="Release Month")
   parser.add_option("-c", "--drop", dest="drop", help="Release Drop")
   parser.add_option("", "--create-ini", action="store_true", dest="createIni", help="Create / update an .ini file", default=False)
   parser.add_option("", "--ini-ignore-types", dest="ignoreTypes", help="Ignore entity types", default="")
   parser.add_option("", "--env-props", action="store_true", dest="envProps", help="Copy envSettings.props", default=False)
   parser.add_option("", "--kps", action="store_true", dest="kps", help="Export KPS JSON files from API Connect and load into KPS", default=False)
#   parser.add_option("", "--kps", dest="kpsSource", help="Export KPS JSON files from API Connect and load into KPS")
   parser.add_option("", "--kpsDebug", action="store_true", dest="kpsDebug", help="Debug Export of KPS JSON files from APIC", default=False)   
#   parser.add_option("", "--copy-jars", action="store_true", dest="copyJars", help="Copy JAR files to target hosts", default=False)
   (options, args) = parser.parse_args(args=copyargs)

   if options.fromSource:
      print "   Promoting from source: " + options.fromSource
   if options.toTarget:
      print "   Promoting to target: " + options.toTarget
   if options.deploy:
      print "   Deploy to target environment"
   if options.save:
      print "   Target deployment package will be saved"
   if options.month:
      print "   Release month: " + options.month
   if options.drop:
      print "   Release drop: " + options.drop
   if options.createIni:
      print "   INI file will be created for target"
   if options.ignoreTypes:
      print "   Entitiy types to ignore during INI creation: " + options.ignoreTypes
   if options.envProps:
      print "   Deploy envSettings.props to target"
   if options.kps:
      print "   Export KPS JSON files from API Connect and load into KPS"

   return options


### MAIN ###

# Setup directories
scriptDir, fedDir, backupDir, svnDir, jarsDir, kpsDir, apicExport = buildDirectories(os.path.dirname(os.path.realpath(sys.argv[0])))

# Parse the input arguments
options = parseOptions(sys.argv[:])

# Check for the target to deploy to
if not options.toTarget:
   print;print "Please provide a target for the deployment package."
   exit()

if options.envProps or options.deploy:
   to_inifile, to_envDir, to_envName = getIniFile(scriptDir, options.toTarget)
   try:
      print;print "Copying envSettings.props to target..."
      command = []
      command.append(scriptDir + "/copyEnvSettings.sh")
      command.append(to_envName)
      copyEnvSettings = subprocess.check_call(command)
      print "   Copy is complete."
   except subprocess.CalledProcessError:
      print "   Copy failed."
      print "   " + str(subprocess.CalledProcessError.returncode)
      print "   " + subprocess.CalledProcessError.cmd
      print "   " + subprocess.CalledProcessError.output
      exit()

   if not (options.save or options.deploy or options.createIni):
      print;print "No action given.  Execute 'jython deployAPI.py -h' to display options."
      exit()

if options.save or options.deploy or options.kps or options.kpsDebug:
   # Check for release information
   if options.month:
      releaseMonth = options.month
   elif options.save or options.deploy:
      print "Provide a release month (eg. Sept2016)"
      exit()

   if options.drop:
      releaseDrop = options.drop
   elif options.save or options.deploy:
      print "Provide a release code drop (eg. CD3)"
      exit()
      
   svnDir = svnDir + releaseMonth.lower() + '/' + releaseDrop.lower() + '/'
   if not os.path.isdir(svnDir):
      print 'The directory ' + svnDir + ' is not found.'
      exit()

   if options.kps or options.kpsDebug:
      if 'PROD' in options.toTarget:
         kpsEnv = 'Prod'
      else:
         kpsEnv = 'NonProd'
      kpsSource = svnDir + 'KPS/' + kpsEnv + '/'
      if not os.path.isdir(kpsSource):
         print 'The directory ' + kpsSource + ' is not found.'
         exit()
      apicExportInput = apicExport + releaseMonth.lower() + '/' + releaseDrop.lower() + '/' + kpsEnv + '/APIC_Scripts_Input'
      if not os.path.isfile(apicExportInput):
         print 'The file ' + apicExportInput + ' is not found.'
         exit()
      
if options.save or options.deploy:
   # Check for source to deploy from
   if not options.fromSource:
      print "Please provide a source for the deployment package.  It may be a file name (.fed or .ini)."
      exit()

   # Get the source
   if ".fed" in options.fromSource:
      # Input is a fed file
      if os.path.isfile(options.fromSource):
         from_fed = options.fromSource
      elif os.path.isfile(svnDir + options.fromSource):
         from_fed = svnDir + options.fromSource
      else:
         print;print "The " + options.fromSource + " file is not found."
         exit()
      print;print "Source FED file: " + from_fed
      from_nm = ""
   else:
      # Input is an ini file
      from_inifile, from_envDir, from_envName = getIniFile(scriptDir, options.fromSource)
      if os.path.isfile(from_inifile):
         print;print "Source INI file: " + from_inifile
         from_ini = ConfigParser.RawConfigParser()
         from_ini.optionxform = str 
         from_ini.read(from_inifile)
         from_nm = from_ini.get('Locations', 'admin_node_mgr')
         print "   Source Admin Node Manager: " + from_nm
         fromGroup = from_ini.get('Locations', 'group')
         print "   Source Group: " + fromGroup
         fromServer = from_ini.get('Locations', 'server')
         print "   Source Server: " + fromServer
         print
         from_nmUser = raw_input('   Enter admin user for ' + fromGroup + ': ')
         from_nmPassword = getpass.getpass('   Enter password for ' + fromGroup + ': ')
      else:
         print "The " + from_inifile + " file is not found."
         exit()
else:
   from_nm = ''

# Get the target
to_inifile, to_envDir, to_envName = getIniFile(scriptDir, options.toTarget)
if os.path.isfile(to_inifile):
   print;print "Target INI file: " + to_inifile
   to_ini = ConfigParser.RawConfigParser()
   to_ini.optionxform = str 
   to_ini.read(to_inifile)
   to_nm = to_ini.get('Locations', 'admin_node_mgr')
   print "   Target Admin Node Manager: " + from_nm
   toGroup = to_ini.get('Locations', 'group')
   print "   Target Group: " + toGroup
   toServer = to_ini.get('Locations', 'server')
   print "   Target Server: " + toServer
   to_envFile = to_envDir + toGroup + '.env'
   print "   Environment Package File to save: " + to_envFile
   if to_nm == from_nm:
      print;print "   Already have Admin Node Manager credentials from Source"
      to_nmUser = from_nmUser
      to_nmPassword = from_nmPassword
   else:
      print
      to_nmUser = raw_input('   Enter admin user for ' + toGroup + ': ')
      to_nmPassword = getpass.getpass('   Enter password for ' + toGroup + ': ')
else:
   print;print "The " + to_inifile + " file is not found."
   exit()

# Load target deployment package
if to_nm != "" and (options.save or options.deploy or options.createIni):
   # Connects to the Admin Node Manager and downloads a configuration from it
   print;print "Download Target deployment package..."
   to_adminNM = NodeManagerDeployAPI.create(to_nm, to_nmUser, to_nmPassword)
   # check for valid connection
   to_depArchive = to_adminNM.getDeploymentArchiveForServerByName(toGroup, toServer)
   print "   Download completed."

   # Initialize the target Deployment Archive API object
   to_depArchiveAPI = DeploymentArchiveAPI(to_depArchive, "")

# Import custom certificates for target
if options.save or options.deploy or options.createIni:
   es = to_depArchiveAPI.getEntityStoreAPI()
   es = importConfigs(es, scriptDir + to_ini.get('Locations', 'importConfigs'))
   to_depArchiveAPI.deploymentArchive.updateConfiguration(es.es)
   es.close
   print "   Import completed."

# Get the environment package
if options.save or options.deploy or options.createIni:
   toEnv = EnvironmentArchive(to_depArchive)

   # Get Environmentalized Values in target Deployment Package
   to_envEntities = to_depArchiveAPI.getEnvSettings().getEnvSettings()

# Create the target INI file if requested
if options.createIni:
   to_ini = buildIni(to_envEntities, to_ini, options.ignoreTypes)
   writeIni(to_ini, to_inifile)
   exit()

# Load the FED from the node manager or from a file
if options.save or options.deploy:
   if options.toTarget == options.fromSource:
      print;print "Source and Target are the same - setting Source deployment package to Target deployment package."
      from_depArchive = to_depArchive
   elif from_nm != "":
      # Connects to the Admin Node Manager and download deployment package
      print;print "Download Source deployment package..."   
      from_adminNM = NodeManagerDeployAPI.create(from_nm, from_nmUser, from_nmPassword)
      from_depArchive = from_adminNM.getDeploymentArchiveForServerByName(fromGroup, fromServer)
      print "   Download completed."
   else:
      # Open the FED file
      print;print "Open Source FED file..."
      from_depArchive = DeploymentArchive(from_fed)
      print "   Opened FED " + from_fed

   # Get the policy package 
   fromPol = PolicyArchive(from_depArchive)

   # Initialize the source Deployment Archive API object
   from_depArchiveAPI = DeploymentArchiveAPI(from_depArchive, "")

   # Get Environmentalized Values in source Deployment Package
   from_envEntities = from_depArchiveAPI.getEnvSettings().getEnvSettings()

   # Generate environmentalized entities as dictionaries
   print;print "Get Source environmentalized settings..."
   fromEnvDict = getEnvSettingsDict(from_envEntities)
   print;print "Get Target environmentalized settings..."
   toEnvDict = getEnvSettingsDict(to_envEntities)

   # Generate the delta comparison between the environmentalized entities
   updateEnvEntities = {}
   compareEnvEntities(fromEnvDict, toEnvDict, to_ini, updateEnvEntities)

   # Merge the source policy package with the target environment package
   # to create a new target deployment package
   print;print "Merging Source Policy Package and Target Environment Package to create the Target Deployment Package..."
   mergedArchive = DeploymentArchive(fromPol, toEnv)
   to_depArchiveAPI = DeploymentArchiveAPI(mergedArchive, "")

   # Update the target deployment package with the changed environmentalized entities
   updateEnvSettings(updateEnvEntities, to_depArchiveAPI)

   # Check Basic HTTP Auth Passwords are environmentalized   
   checkBasicProfile(to_depArchiveAPI.getEntityStoreAPI())

   # Display the target environmentalized entities
   #displayEnvEntities(to_depArchiveAPI.getEnvSettings().getEnvSettings())

# Update Environment properties
if options.save or options.deploy:
   print; print "Updating enviroment properties..."
   to_depArchiveAPI.updateEnvironmentProps(dict([(Archive.NAME_DEFAULT_PROPERTY, to_ini.get('Locations', 'env_name'))])) 
   to_depArchiveAPI.updateEnvironmentProps(dict([(Archive.DESCRIPTION_DEFAULT_PROPERTY, "Environment Settings for " + to_ini.get('Locations', 'env_name'))])) 
   to_depArchiveAPI.updateEnvironmentProps(dict([(Archive.VERSION_DEFAULT_PROPERTY, 'v' + to_ini.get('Locations', 'env_name') + releaseMonth + releaseDrop)]))
   to_depArchiveAPI.updateEnvironmentProps(dict([(Archive.VERSIONCOMMENT_DEFAULT_PROPERTY, "Updated Environment Settings for " + releaseMonth + " " + releaseDrop)]))

   es = to_depArchiveAPI.getEntityStoreAPI()
   es = importConfigs(es, scriptDir + to_ini.get('Locations', 'importConfigs'))
   to_depArchiveAPI.deploymentArchive.updateConfiguration(es.es)
   es.close
   print "   Import completed."

   # Save the updated target environment package file
   print;print "Saving Target Environment Package..."
   environmentArchive = EnvironmentArchive(mergedArchive)
   environmentArchive.writeToArchiveFile(to_envFile)
   print "   Saved environment package to %s " % (to_envFile)

# Save the updated target deployment package file
if options.save:
   print;print "Saving Target Deployment Package..."
   outFedFile = fedDir + options.toTarget + '.fed'
   mergedArchive.writeToArchiveFile(outFedFile)
   print "   Saved deployment package to %s " % (outFedFile)

# Deploy to To Environment
if options.deploy:
   print;print "Deploying Target Deployment Package..."
   print "   Backing up current target deployment package..."
   backupFed = backupDir + options.toTarget.split('.ini')[0] + '_bak.fed'
   to_depArchive.writeToArchiveFile(backupFed)
   print "      Current target deployment package backed up to " + backupFed
   print "   Deploying..."
   deploy(to_adminNM, toGroup, mergedArchive)
   print "   Deployment complete"
   
# Update KPS
if options.kpsDebug:
#   exportAPICJSON("APIC_Scripts_Input", kpsDir, options.kpsDebug)
   exportAPICJSON(apicExportInput, kpsDir, options.kpsDebug)
elif options.kps or options.deploy:
   # Copy other non-APIC KPS JSON files to temp
   #kpsSource = svnDir + options.kpsSource
   os.system('cp ' + kpsSource + '/*json ' + kpsDir)
   # Export KPS JSON from APIC
#   exportAPICJSON("APIC_Scripts_Input", kpsDir, options.kpsDebug)
   exportAPICJSON(apicExportInput, kpsDir, options.kpsDebug)
   # backup KPS file system
   groupName = to_ini.get('Locations', 'group')
   print groupName
   i = 1
   while True:
      try:
         os.system('ssh wasadm@' + to_ini.get('Locations', 'node' + str(i)) + ' "cd /apps/Axway-7.4/apigateway/instances/' + groupName + '/conf/kps;rm -f cassandra-bak.tgz;tar -zcvf cassandra-bak.tgz cassandra"')
      except ConfigParser.NoOptionError:
         break 
      i += 1
      print i
   # Update KPS
   updateKPS(to_nm, to_nmUser, to_nmPassword, kpsDir, to_ini)
   # Delete APIC KPS JSON files from kpsDir
   os.system('rm -f ' + kpsDir + '/*')   

# Copy JAR Files
#if options.copyJars:
#   copyJars(jarsDir)

