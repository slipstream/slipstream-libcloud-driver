
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
 libcloud get_driver function.

 import slipstream.libcloud.compute_driver
 from libcloud.compute.providers import get_driver
 
 driver = get_driver('slipstream')
"""

import warnings
import traceback

from libcloud.compute.ssh import have_paramiko
from libcloud.compute.base import NodeImage, NodeSize, Node, KeyPair
from libcloud.compute.base import NodeAuthSSHKey, NodeDriver
from libcloud.compute.base import NodeLocation, UuidMixin
from libcloud.compute.base import StorageVolume
from libcloud.compute.types import NodeState
from libcloud.utils.networking import is_public_subnet

from slipstream.api import Api


have_pycrypto = True
try:
    from Crypto.PublicKey import RSA
    # import pycrypto_patch
except ImportError:
    have_pycrypto = False


__all__ = [
    'VirtualMachine',
    'SlipStreamNodeDriver'
]


class VirtualMachine(Node):
    pass

class SlipStreamNodeDriver(NodeDriver):

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

        #super(NodeDriver, self).__init__(key=key, secret=secret, secure=secure,
        #                                 host=host, port=port,
        #                                 api_version=api_version, **kwargs)
       
        insecure = not secure
        endpoint = kwargs.get('ex_endpoint')
        cookie_file = kwargs.get('cookie_file')

        if not endpoint:
            scheme = 'https' if secure else 'http'
            port = ':{}'.format(port) if port else ''
            endpoint = '{}://{}{}'.format(scheme, host, port)

        self.ss_api = Api(endpoint=endpoint, 
                          cookie_file=cookie_file,
                          insecure=insecure)
                          
        if not cookie_file:
            self.ss_api.login(key, secret)

    def list_nodes(self):
        deployments = self.ss_api.list_deployments()
        return [self._deployment_to_node(depl) for depl in deployments]

    def list_sizes(self, location=None):
        filter = 'resource:type="VM"'
        
        if location:
            filter += ' and connector/href = "{}"'.format(location)
        
        service_offers = self.ss_api.cimi_search('serviceOffers', filter=filter)

        return [self._service_offer_to_size(so) 
                for so in service_offers.json.get('serviceOffers', [])]

    def list_locations(self):
        return list(self.ss_api.get_user().configured_clouds)

    def create_node(self, **kwargs):
        name = kwargs.get('name')
        size = kwargs.get('size')
        image = kwargs.get('image')
        location = kwargs.get('location')
        
        tags = kwargs.get('ex_tags', [])
        cloud = kwargs.get('ex_cloud')
        parameters = kwargs.get('ex_parameters')
        keep_running = kwargs.get('ex_keep_running')
        multiplicity = kwargs.get('ex_multiplicity')
        tolerate_failures = kwargs.get('ex_tolerate_failures')
        check_ssh_key = kwargs.get('ex_check_ssh_key', False)
        scalable = kwargs.get('ex_scalable', False)
        
        cloud = cloud or location
        tags = [tags] if isinstance(tags, basestring) else tags
        tags = [name] + tags

        return self.ss_api.deploy(path=image.id,
                                  cloud=cloud,
                                  parameters=parameters,
                                  tags=tags,
                                  keep_running=keep_running,
                                  scalable=scalable,
                                  multiplicity=multiplicity,
                                  tolerate_failures=tolerate_failures,
                                  check_ssh_key=check_ssh_key)

    def destroy_node(self, node):
        try:
            return self.ss_api.terminate(node.id)
        except Exception as e:
            warnings.warn('Exception while destroying node "{}": {}'
                          .format(node.name, 
                                  traceback.format_exc, 
                                  RuntimeWarning))
            return False
    
    def list_images(self, location=None, path=None, recurse=False):
        if path is None:
            elements = self.ss_api.list_applications()
        else:
            path = path.lstrip('/')
            elements = self.ss_api.list_project_content(path=path,
                                                        recurse=recurse)
        return [self._element_to_image(el)
                for el in elements if el.type in ['component', 'application']]

    def delete_image(self, node_image):
        return self.ss_api.delete_element(path=node_image.id)

    def get_image(self, image_id):
        return self._element_to_image(self.ss_api.get_element(path=image_id))

    def list_key_pairs(self):
        return [self._ssh_public_key_to_key_pair(kp)
                for kp in self.ss_api.get_user().ssh_public_keys if kp]

    def get_key_pair(self, name):
        return self._list_key_pairs_by_names().get(name)

    def create_key_pair(self, name):
        if not have_pycrypto:
            raise RuntimeError('create_key_pair require pyCrypto')

        rsa_keypair = RSA.generate(2048)
        private_key_pem = rsa_keypair.exportKey()
        public_key_openssh = rsa_keypair.publickey().exportKey(format='OpenSSH')
        
        key_pair = self._ssh_public_key_to_key_pair(public_key_openssh, name)
        key_pair.private_key = private_key_pem
        
        #public_key_openssh_full = '{} {}'.format(public_key_openssh, name)
        
        self._add_ssh_public_key(key_pair.public_key)
        
        return key_pair
        
        #return KeyPair(name=name,
        #               fingerprint=None,
        #               public_key=public_key_openssh_full,
        #               private_key=private_key_pem)

    def import_key_pair_from_string(self, name, key_material):
        key_pair = self._ssh_public_key_to_key_pair(key_material, name)
        
        self._add_ssh_public_key(key_pair.public_key)
        
        return key_pair
        
    def import_key_pair_from_file(self, name, key_file_path):
        with open(key_file_path, 'r') as f:
            ssh_public_key = f.read()
        return self.import_key_pair_from_string(name, ssh_public_key)
    
    def delete_key_pair(self, key_pair):
        key_pairs = self._list_key_pairs_by_names()
        del key_pairs[key_pair.name]
        
        ssh_public_keys = '\n'.join([kp.public_key for kp in key_pairs.values()])

        return self.ss_api.update_user(ssh_public_keys=ssh_public_keys)

    def ex_list_virtual_machines(self, location=None, node=None):
        #deployment_id = node.id if node else None
        #return list(self.ss_api.list_virtualmachines(deployment_id=deployment_id, cloud=location))
        
        filters = []
        
        if location:
            filters.append('connector/href = "connector/{}"'.format(location))
            
        if node:
            filters.append('deployment/href = "run/{}"'.format(node.id))
            
        filter = ' and '.join(filters) or None
        
        virtual_machines = self.ss_api.cimi_search('virtualMachines', filter=filter)

        return [self._virtual_machine_to_node(vm)
                for vm in virtual_machines.json.get('virtualMachines', [])]

    def _state_to_node_state(self, state):
        return self.NODE_STATE_MAP.get(state.lower(),
                                       NodeState.UNKNOWN)
                                       
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














