
#
# (C) Copyright 2017 SixSq (http://sixsq.com/).
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
 Libcloud compute driver for SlipStream (http://sixsq.com/slipstream).

 To use this driver please import this file and then use the usual
 libcloud get_driver function.::

    import slipstream.libcloud.compute_driver
    from libcloud.compute.providers import get_driver
 
    slipstream_driver = get_driver('slipstream')
 
 
 Examples
 --------

 Login on Nuvla with username and password
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::

    ss = slipstream_driver('username', 'password')


 Login on Nuvla with key and secret
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::

    ss = slipstream_driver('credential/ce02ef40-1342-4e68-838d-e1b2a75adb1e', 
                           'the-secret-key', 
                           ex_login_method='api-key')


 List Images from the App Store
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::

    from pprint import pprint as pp
    pp(ss.list_images())


 List base Images
 ~~~~~~~~~~~~~~~~
 ::

    from pprint import pprint as pp
    pp(ss.list_images(ex_path='examples/images'))


 Simple node creation (WordPress server)
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::
 
    # Get the WordPress image
    image = ss.get_image('apps/WordPress/wordpress')
    
    # Create the Node
    node = ss.create_node(image=image)
 
 
 Complete application (node) deployment (WordPress server)
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::
 
    # Get the WordPress image
    image = ss.get_image('apps/WordPress/wordpress')
    
    # WordPress Title
    wordpress_title = 'WordPress deployed by SlipStream through Libcloud'
    
    # Create the dict of parameters to (re)define
    parameters = dict(wordpress_title=wordpress_title)
    
    # Create the Node
    node = ss.create_node(image=image, ex_parameters=parameters)
    
    # Wait the node to be ready
    ss.ex_wait_node_in_state(node)
    
    # Update the node
    node = ss.ex_get_node(node.id)
    
    # Print the WordPress URL
    print node.extra.get('service_url')
    


"""

import time
import warnings
import traceback

from libcloud.compute.ssh import have_paramiko
from libcloud.compute.base import NodeImage, NodeSize, Node, KeyPair
from libcloud.compute.base import NodeAuthSSHKey, NodeDriver
from libcloud.compute.base import NodeLocation, UuidMixin
from libcloud.compute.base import StorageVolume
from libcloud.compute.types import NodeState, LibcloudError
from libcloud.utils.networking import is_public_subnet

from slipstream.api import Api


have_pycrypto = True
try:
    from Crypto.PublicKey import RSA
except ImportError:
    have_pycrypto = False


__all__ = [
    'VirtualMachine',
    'SlipStreamNodeDriver'
]


class VirtualMachine(Node):
    """
    A SlipStream Virtual Machine
    """
    pass


class SlipStreamNodeDriver(NodeDriver):

    """
    SlipStream node driver

    Note: This driver manage KeyPair in a slighty different way than others.
          All configured key pairs are added to VMs at the creation of VMs.
    """

    name = 'SlipStream'
    type = 'slipstream'
    website = 'https://sixsq.com/slipstream'

    features = {'create_node': []}

    NODE_STATE_MAP = {
        # Deployment states
        'initializing': NodeState.PENDING,
        'provisioning': NodeState.REBOOTING, #STARTING,
        'executing': NodeState.RUNNING, #RECONFIGURING,
        'sendingReports': NodeState.RUNNING, #RECONFIGURING,
        'ready': NodeState.RUNNING,
        'finalizing': NodeState.RUNNING, #STOPPING,
        'done': NodeState.TERMINATED,
        'aborted': NodeState.ERROR,
        'cancelled': NodeState.TERMINATED,
        # VirtualMachine states
        'rebooting': NodeState.REBOOTING,
        'poweroff': NodeState.STOPPED,
        'running': NodeState.RUNNING,
        'stopped': NodeState.STOPPED,
        'deleted': NodeState.TERMINATED,
        'terminated': NodeState.TERMINATED,
        'error': NodeState.ERROR,
        'stopping': NodeState.RUNNING,
        'failed': NodeState.ERROR,
        'pending': NodeState.PENDING,
        'paused': NodeState.PAUSED,
        'suspended': NodeState.PAUSED,
    }

    def __init__(self, key, secret=None, secure=True, host='nuv.la', port=None,
                 api_version=None, **kwargs):
        """
        Instanciate a SlipStream node driver.

        :param      key:  Username or API key
        :type       key:  ``str``

        :param      secret:  Password or Secret key
        :type       secret:  ``str``

        :param      secure:  Use secure (HTTPS) connection
        :type       secure:  ``bool``

        :param      host:  Hostname of the SlipStream endpoint (default: nuv.la)
        :type       host:  ``str``

        :param      port:  Port of the SlipStream endpoint (default: 443 if secure else 80)
        :type       port:  ``int``

        :param      api_version:  [Unused]
        :type       api_version:  ``str``

        :keyword    ex_endpoint:  The SlipStream endpoint (example: https://nuv.la)
        :type       ex_endpoint:  ``str``

        :keyword    ex_cookie_file:  Path to a existing cookie file to use instead of key and secret
        :type       ex_cookie_file:  ``str``

        :keyword    ex_login_method:  Login method (internal for username/password and api-key for key/secret)
        :type       ex_login_method:  ``str``
        
        :keyword    ex_login_parameters: Extra parameters to provide to the login method
        :type       ex_login_parameters: ``dict``
        """
        
        insecure = not secure
        endpoint = kwargs.get('ex_endpoint')
        cookie_file = kwargs.get('ex_cookie_file')
        login_method = kwargs.get('ex_login_method', 'internal')
        login_parameters = kwargs.get('ex_login_parameters', {})

        if not endpoint:
            scheme = 'https' if secure else 'http'
            port = ':{}'.format(port) if port else ''
            endpoint = '{}://{}{}'.format(scheme, host, port)

        self.ss_api = Api(endpoint=endpoint, 
                          cookie_file=cookie_file,
                          insecure=insecure)
                          
        if not cookie_file:
            login_params = {}
            
            if login_parameters:
                login_params.update(login_parameters)
                
            if login_method:
                login_params['href'] = 'session-template/{}'.format(login_method)
                
                if login_method == 'internal':
                    if key:
                        login_params['username'] = key
                    if secret:
                        login_params['password'] = secret
                        
                elif login_method == 'api-key':
                    if key:
                        login_params['key'] = key
                    if secret:
                        login_params['secret'] = secret
            
            self.ss_api.login(login_params)

    def list_nodes(self):
        """
        List Nodes (SlipStream deployments)

        :return:    List of node objects
        :rtype:     ``list`` of :class:`Node`
        """
        deployments = self.ss_api.list_deployments()
        return [self._deployment_to_node(depl) for depl in deployments]

    def list_sizes(self, location=None):
        """
        List Sizes (SlipStream service offers)

        :param    location:  Return only sizes for the specified location
        :type     location:  :class:`NodeLocation`

        :return:  List of node size objects
        :rtype:   ``list`` of :class:`.NodeSize`
        """
        filter = 'resource:type="VM"'
        
        if location:
            filter += ' and connector/href = "{}"'.format(location.name)
        
        service_offers = self.ss_api.cimi_search('serviceOffers', filter=filter)

        return [self._service_offer_to_size(so) 
                for so in service_offers.json.get('serviceOffers', [])]

    def list_locations(self):
        """
        List Locations (SlipStream cloud connectors)

        :return:  List of node location objects
        :rtype:   ``list`` of :class:`NodeLocation`
        """
        return [self._cloud_to_location(cloud)
                for cloud in self.ss_api.get_user().configured_clouds]

    def create_node(self, **kwargs):
        """Create a new Node (deploy an application or a component)

        :keyword  name:  Name of the node (set as a SlipStream Tag). (optional)
        :type     name:  ``str``

        :keyword  size:  Size of Cloud resources (SlipStream serviec offer). (optional)
                         If not provided the default of each VM will be used.
                         If provided the size will be applied to all VM.
        :type     size:  :class:`NodeSize`

        :keyword  image:  Image to deploy (SlipStream application or component). (required)
        :type     image:  :class:`NodeImage`

        :keyword  location:  Location where to create the node (SlipStream cloud). (optional)
                             If provided all VM will be started in the specified location.
                             If not provided the default location will be used.
        :type     location:  :class:`NodeLocation`

        :keyword  ex_tags:  List of tags that can be used to identify or annotate a node.
        :type     ex_tags:  ``str`` or ``list``

        :keyword  ex_cloud:  To be used instead of location to specify the Cloud name
                             on which to start VMs.
                             To deploy a component simply specify the Cloud name as a string.
                             To deploy a deployment specify a dict with the nodenames as keys 
                             and Cloud names as values.
        :type     ex_cloud:  ``str`` or ``dict``

        :keyword  ex_parameters:  Parameters to (re)define for this image.
                           To redefine a parameter of a SlipStream application's node 
                           use "<nodename>" as keys and dict of parameters as values.
                           To redefine a parameter of a SlipStream component or 
                           a global parameter use "<parametername>" as the key.
        :type     ex_parameters:  ``dict``

        :keyword  ex_keep_running:  [Only apply to SlipStream applications] 
                                    Define when to terminate or not a deployment 
                                    when it reach the 'Ready' state. 
                                    If scalable is set to True, this value is ignored 
                                    and it will behave as if it was set to 'always'.
        :type     ex_keep_running:  'always' or 'never' or 'on-success' or 'on-error'

        :keyword  ex_multiplicity:  [Only apply to SlipStream applications]
                                    A dict to specify how many instances to start 
                                    per application's node.
                                    Application's sodenames as keys and number of 
                                    instances to start as values.
        :type     ex_multiplicity:  ``dict``

        :keyword  ex_tolerate_failures:  [Only apply to SlipStream applications]
                                         A dict to specify how many failures to tolerate
                                         per application's node.
                                         Nodenames as keys and number of failure to 
                                         tolerate as values.
        :type     ex_tolerate_failures:  ``dict``

        :keyword  ex_check_ssh_key:  Set it to True if you want the SlipStream server 
                                     to check if you have a public ssh key defined. 
                                     Useful if you want to ensure you will have access to VMs.
        :type     ex_check_ssh_key:  ``bool``

        :keyword  ex_scalable:  [Only apply to SlipStream applications]
        :type     ex_scalable:  True to start a scalable deployment. (default: False)

        :return:  The newly created node.
        :rtype:   :class:`Node`

        """
        name = kwargs.get('name')
        size = kwargs.get('size')
        image = kwargs.get('image')
        location = kwargs.get('location')
        
        tags = kwargs.get('ex_tags', [])
        cloud = kwargs.get('ex_cloud')
        parameters = kwargs.get('ex_parameters', {})
        keep_running = kwargs.get('ex_keep_running')
        multiplicity = kwargs.get('ex_multiplicity')
        tolerate_failures = kwargs.get('ex_tolerate_failures')
        check_ssh_key = kwargs.get('ex_check_ssh_key', False)
        scalable = kwargs.get('ex_scalable', False)
        
        path = image.id
        element = self.ss_api.get_element(path)
        
        if not cloud and location:
            if element.type == 'application':
                cloud = {}
                for element_node in self.ss_api.get_application_nodes(path):
                    cloud[element_node.name] = location.name
            else:
                cloud = location.name
                
        if size:
            if element.type == 'application':
                for app_node in self.ss_api.get_application_nodes(path):
                    node_params = parameters.setdefault(element_node.name, {})
                    if 'service-offer' not in node_params:
                        node_params['service-offer'] = size.id
            else:
                if 'service-offer' not in parameters:
                    parameters['service-offer'] = size.id
        
        tags = [tags] if isinstance(tags, basestring) else tags
        if name:
            tags = [name] + tags

        node_id = self.ss_api.deploy(path=path,
                                    cloud=cloud,
                                    parameters=parameters,
                                    tags=tags,
                                    keep_running=keep_running,
                                    scalable=scalable,
                                    multiplicity=multiplicity,
                                    tolerate_failures=tolerate_failures,
                                    check_ssh_key=check_ssh_key)
        return self.ex_get_node(node_id)

    def destroy_node(self, node):
        """"
        Destroy a node.

        :param    node:  The node to be destroyed
        :type     node:  :class:`Node`

        :return:  True if the destroy was successful, False otherwise.
        :rtype:   ``bool``
        """
        try:
            return self.ss_api.terminate(node.id)
        except Exception as e:
            warnings.warn('Exception while destroying node "{}": {}'
                          .format(node.name, 
                                  traceback.format_exc(),
                                  RuntimeWarning))
            return False
    
    def list_images(self, location=None, ex_path=None, ex_recurse=False):
        """ List images (SlipStream components and applications)

        :param    location:  [NOT IMPLEMENTED] 
                             Return only images for the specified location
        :type     location:  :class:`NodeLocation`

        :param    ex_path:  Path on which to search for images. (optional)
                            If not provided it will list the content of the
                            App Store.
        :type     ex_path:  ``str``

        :param    ex_recurse: Recurse into subprojects. (default: False)
                              Setting this value to True can be expensive.

        :return:  list of node image objects.
        :rtype:   ``list`` of :class:`NodeImage`
        """
        if ex_path is None:
            elements = self.ss_api.list_applications()
        else:
            ex_path = ex_path.lstrip('/')
            elements = self.ss_api.list_project_content(path=ex_path,
                                                        recurse=ex_recurse)
        return [self._element_to_image(el)
                for el in elements if el.type in ['component', 'application']]

    def delete_image(self, node_image):
        """
        Deletes a node image from a provider.

        :param    node_image:  Node image object.
        :type     node_image:  :class:`NodeImage`

        :return:  ``True`` if delete_image was successful, ``False`` otherwise.
        :rtype:   ``bool``
        """
        try:
            return self.ss_api.delete_element(path=node_image.id)
        except Exception as e:
            warnings.warn('Exception while deleting image "{}": {}'
                          .format(node.name,
                                  traceback.format_exc(),
                                  RuntimeWarning))
        return False

    def get_image(self, image_id):
        """
        Get an image from it's image_id

        :param    image_id:  Image ID (SlipStream path)
        :type     image_id:  ``str``

        :return:  NodeImage instance on success.
        :rtype:   :class:`NodeImage`:
        """
        return self._element_to_image(self.ss_api.get_element(path=image_id))

    def list_key_pairs(self):
        """
        List all the available key pair objects.

        :return:  List of configured key pairs
        :rtype:   ``list`` of :class:`KeyPair` objects
        """
        return [self._ssh_public_key_to_key_pair(kp)
                for kp in self.ss_api.get_user().ssh_public_keys if kp]

    def get_key_pair(self, name):
        """
        Retrieve a single key pair.

        :param    name:  Name of the key pair to retrieve.
        :type     name:  ``str``

        :return:  A key pair
        :rtype:   :class:`KeyPair`
        """
        return self._list_key_pairs_by_names().get(name)

    def create_key_pair(self, name):
        """
        Create a new key pair object.

        This operation require a working PyCrypto installation with RSA object

        :param name:    Key pair name.
        :type name:     ``str``
        """
        if not have_pycrypto:
            raise RuntimeError('create_key_pair require pyCrypto')

        rsa_keypair = RSA.generate(2048)
        private_key_pem = rsa_keypair.exportKey()
        public_key_openssh = rsa_keypair.publickey().exportKey(format='OpenSSH')
        
        key_pair = self._ssh_public_key_to_key_pair(public_key_openssh, name)
        key_pair.private_key = private_key_pem
        
        self._add_ssh_public_key(key_pair.public_key)
        
        return key_pair

    def import_key_pair_from_string(self, name, key_material):
        """
        Import a new public key from string.

        :param    name:  Key pair name.
        :type     name:  ``str``

        :param    key_material:  Public key material.
        :type     key_material:  ``str``

        :return:  The key pair
        :rtype:   :class:`KeyPair` object
        """
        key_pair = self._ssh_public_key_to_key_pair(key_material, name)
        
        self._add_ssh_public_key(key_pair.public_key)
        
        return key_pair
        
    def import_key_pair_from_file(self, name, key_file_path):
        """
        Import a new public key from string.

        :param    name:  Key pair name.
        :type     name:  ``str``

        :param    key_file_path:  Path to the public key file.
        :type     key_file_path:  ``str``

        :return:  The key pair
        :rtype:   :class:`KeyPair` object
        """
        with open(key_file_path, 'r') as f:
            ssh_public_key = f.read()
        return self.import_key_pair_from_string(name, ssh_public_key)
    
    def delete_key_pair(self, key_pair):
        """
        Delete an existing key pair.

        :param    key_pair:  Key pair object.
        :type     key_pair:  :class:`KeyPair`
        """
        key_pairs = self._list_key_pairs_by_names()
        del key_pairs[key_pair.name]
        
        ssh_public_keys = '\n'.join([kp.public_key for kp in key_pairs.values()])

        return self.ss_api.update_user(ssh_public_keys=ssh_public_keys)

    def ex_get_node(self, node_id):
        """
        Get a node from it's ID
        
        :param    node_id:  ID of the node to retrieve
        :type     node_id:  ``str`` or :class:`UUID`
        
        :return:    The requested node
        :rtype:     :class:`Node`
        """
        return self._deployment_to_node(self.ss_api.get_deployment(node_id))
        
    def ex_wait_node_in_state(self, node, states='Ready', wait_period=10,
                              timeout=600, ignore_abort=False):
        """
        Wait a node to be in one of the specified states (default: Ready)
        
        :param    states:  The names of the states to wait for. (default: Ready)
        :type     states:  ``str`` or ``list``
        
        :param    wait_period:  How many seconds to wait between each loop iteration. (default: 10)
        :type     wait_period: ``int``
        
        :param    timeout:  How many seconds to wait before giving up. (default: 600)
        :type     timeout: ``int``
        
        :param    ignore_abort: If False, raise an exception if the node has failed
        :type     ignore_abort: ``bool``
        
        :return:    The state that was reached or raise a LibcloudError if timeout
        :rtype:     ``str``
        """
        _states = [states] if isinstance(states, basestring) else states
        deadline = time.time() + timeout
        
        while time.time() < deadline:
            state = self.ss_api.get_deployment_parameter(node.id, 'ss:state', 
                                                         ignore_abort)
            if state in _states:
                return state
            
            time.sleep(wait_period)
        
        raise LibcloudError(value='Timed out after %s seconds' % (timeout),
                            driver=self)

    def ex_list_virtual_machines(self, location=None, node=None):
        """
        List Virtual Machines (SlipStream virtual machines)

        :param    location:  Return only virtual machines for the specified location
        :type     location:  :class:`NodeLocation`

        :param    node:  List VM belonging to the specified node
        :type     node:  :class:`Node`

        :return:    List of virtualmachine objects
        :rtype:     ``list`` of :class:`VirtualMachine`
        """
        filters = []
        
        if location:
            filters.append('connector/href = "connector/{}"'.format(location.name))
            
        if node:
            filters.append('deployment/href = "run/{}"'.format(node.id))
            
        filter = ' and '.join(filters) or None
        
        virtual_machines = self.ss_api.cimi_search('virtualMachines', filter=filter)

        return [self._virtual_machine_to_node(vm)
                for vm in virtual_machines.json.get('virtualMachines', [])]

    def _state_to_node_state(self, state):
        return self.NODE_STATE_MAP.get(state.lower(),
                                       NodeState.UNKNOWN)
                                       
    def _cloud_to_location(self, cloud):
        country = None
        try:
            filter = 'resource:type="VM" and connector/href = "{}"'.format(cloud)
            service_offer = self.ss_api.cimi_search('serviceOffers', 
                                                    filter=filter, 
                                                    end=1)
            country = service_offer.json['serviceOffers'][0]['resource:country']
        except Exception as e:
            pass
        
        return NodeLocation(id='connector/{}'.format(cloud),
                            name=cloud,
                            country=country,
                            driver=self)
                                       
    def _deployment_to_node(self, deployment):
        return Node(id=str(deployment.id),
                    name=str(deployment.id),
                    state=self._state_to_node_state(deployment.status),
                    public_ips=None,
                    private_ips=None,
                    driver=self,
                    size=None,
                    image=deployment.module,
                    #created_at=deployment.started_at,
                    extra=dict(deployment._asdict()))

    def _service_offer_to_size(self, service_offer):
        return NodeSize(id=service_offer.get('id'),
                        name=service_offer.get('name'),
                        ram=service_offer.get('resource:ram'),
                        disk=service_offer.get('resource:disk'),
                        bandwidth=None,
                        price=service_offer.get('price:unitCost'),
                        driver=self,
                        extra=service_offer)
                        
    def _element_to_image(self, element):
        return NodeImage(id='{}/{}'.format(element.path, element.version),
                         name=element.name,
                         driver=self,
                         extra=dict(element._asdict()))
                         
    def _virtual_machine_to_node(self, virtual_machine):
        ip = virtual_machine.get('ip')
        state = virtual_machine.get('state', 'unknown')

        public_ips = None
        private_ips = None
        try:
            if is_public_subnet(ip):
                public_ips = [ip]
            else:
                private_ips = [ip]
        except:
            pass
        
        return VirtualMachine(id=virtual_machine.get('id'),
                              name=virtual_machine.get('instanceID'),
                              state=self._state_to_node_state(state),
                              public_ips=public_ips,
                              private_ips=private_ips,
                              driver=self,
                              size=virtual_machine.get('serviceOffer', {}).get('href'),
                              image=None,
                              #created_at=virtual_machine.get('created'),
                              extra=dict(virtual_machine))

    def _list_key_pairs_by_names(self):
        return dict([(kp.name, kp) for kp in self.list_key_pairs() 
                     if kp and kp.name])

    def _ssh_public_key_to_key_pair(self, ssh_public_key, name=None):
        key_type, key_content, key_name = self._parse_ssh_public_key(ssh_public_key)
                             
        public_key_name = name if name else key_name                   
        public_key = '{} {} {}'.format(key_type, key_content, public_key_name)
            
        return KeyPair(name=public_key_name,
                       public_key=public_key,
                       fingerprint=None,
                       driver=self,
                       extra={'public_key_type': key_type,
                              'public_key_content': key_content})
                              
    def _parse_ssh_public_key(self, ssh_public_key):
        try:
            key = ssh_public_key.strip('\t\r\n ').split(' ', 2)
            key_type = key[0]
            key_content = key[1]
            key_name = key[2] if len(key) > 2 else ''
        except Exception:
            raise ValueError('Invalid OpenSSH key format for key: {}'
                             .format(ssh_public_key))
        return key_type, key_content, key_name
                              
    def _add_ssh_public_key(self, ssh_public_key):
        user_public_keys = self.ss_api.get_user().ssh_public_keys
        
        user_public_keys.append(ssh_public_key)
        ssh_public_keys = '\n'.join(user_public_keys)
        
        return self.ss_api.update_user(ssh_public_keys=ssh_public_keys)



from libcloud.compute.providers import set_driver
set_driver('slipstream',
           'slipstream.libcloud.compute_driver',
           'SlipStreamNodeDriver')


