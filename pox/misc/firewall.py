# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Firewall
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time

from pox.lib.addresses import EthAddr

log = core.getLogger()
f = open("Firewall_Log.txt", "w")
# The switch should not flood immediately after it is connected.
_flood_delay = 10

class LearningSwitch (object):
  """
  From the switch, for each packet sent:
  1) Update the address/port table using the source address and switch port
  2) If the rule does not exist in the firewall: Drop the packet 
  3) Is there a port for destination address in our address/port table? No: Flood the packet
  4) Does the output port match the input port? Yes: Drop packet
  5) Create an entry in the switch's flow table so that this flow goes out the proper port: Send packet
  """

  def __init__ (self, connection):
    self.connection = connection

    log.debug("Initializing Firewall LearningSwitch")
    f.write("Initializing Firewall LearningSwitch" + '\n')

    # table
    self.macToPort = {}

    # firewall table
    self.firewall = {}

    # Firewall Rules
    self.AddRule('00-00-00-00-00-01',EthAddr('00:00:00:00:00:01'))
    self.AddRule('00-00-00-00-00-01',EthAddr('00:00:00:00:00:02'))
    self.AddRule('00-00-00-00-00-01',EthAddr('00:00:00:00:00:03'))
    


    # Hear PacketIn messages: Listen to the connection
    connection.addListeners(self)
 
    self.hold_down_expired = _flood_delay == 0

  # Adding firewall rules into the firewall table
  def AddRule (self, dpidstr, src=0,value=True):
    self.firewall[(dpidstr,src)]=value
    log.debug("Adding firewall rule in %s: %s", dpidstr, src)
    f.write("Adding firewall rule in " + str(dpidstr) +": " + str(src) +"\n")

  # # Deleting firewall rules from the firewall table
  # def DeleteRule (self, dpidstr, src=0):
  #    try:
  #      del self.firewall[(dpidstr,src)]
  #      log.debug("Deleting firewall rule in %s: %s",
  #                dpidstr, src)
  #    except KeyError:
  #      log.error("Deleting Rule: Cannot find in %s: %s",
  #                dpidstr, src)


  # Verify that the packet follows the rules before moving forward.
  def CheckRule (self, dpidstr, src=0):
    try:
      entry = self.firewall[(dpidstr, src)]
      if (entry == True):
        log.debug("Rule (%s) found in %s: FORWARD",
                  src, dpidstr)
      else:
        log.debug("Rule (%s) found in %s: DROP",
                  src, dpidstr)
      return entry
    except KeyError:
      log.debug("Rule (%s) NOT found in %s: DROP",
                src, dpidstr)
      return False

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch.
    """
    log.debug("_handle_packetIn")
    f.write("_handle_packetIn" + '\n')

    packet = event.parsed
    
    # ofp_packet_in
    log.debug(event.ofp)
    f.write('\n\n\n' + str(event.ofp) + '\n\n\n')
    f.write("event.dpid: " + str(dpid_to_str(event.dpid)) + ", packet.src: " + str(packet.src) + ", packet.dst: " + str(packet.dst) + "\n")
    # log.debug("event.parsed.find('tcp') to find the TCP header in the packet")
    # # For example, you can use event.parsed.find('tcp') to find the TCP header in the packet, 
    # log.debug(event.parsed.find('tcp'))
    
    # log.debug("event.parsed.dump() to print the entire packet contents")
    # # or event.parsed.dump() to print the entire packet contents
    # log.debug(event.parsed.dump())

    # log.debug("event.data")
    # # event.data
    # log.debug(event.data)


    log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)

    def flood (message = None):
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        if self.hold_down_expired is False:
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))
        if message is not None: 
          log.debug("massage is not None ")
        log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)

        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        log.info("Holding down flood for %s", dpid_to_str(event.dpid))
        pass
        
      msg.data = event.ofp
      msg.in_port = event.port
      f.write("Flood" + '\n')
      f.write('\n\n\n' + str(msg) + '\n\n\n')
      self.connection.send(msg)

    def drop ():
      """
      Drops this packet 
      """

      # if duration is not None:
      #   if not isinstance(duration, tuple):
      #     duration = (duration,duration)
      #   msg = of.ofp_flow_mod()
      #   msg.match = of.ofp_match.from_packet(packet)
      #   msg.idle_timeout = duration[0]
      #   msg.hard_timeout = duration[1]
      #   msg.buffer_id = event.ofp.buffer_id
      #   log.debug("Drop with duration: ", duration[0])
      #   self.connection.send(msg)
      # elif 
      # if event.ofp.buffer_id is not None:
      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      log.debug("Drop the packet")
      f.write("Drop" + '\n')
      f.write('\n\n\n' + str(msg) + '\n\n\n')
      self.connection.send(msg)
    

    
    self.macToPort[packet.src] = event.port # 1

    # DPID of the Switch Connection
    dpidstr = dpid_to_str(event.connection.dpid)

    # Check the Firewall Rules
    if self.CheckRule(dpidstr, packet.src) == False:
      log.debug("CheckRule is False: 2:Drop")
      drop()
      return


    if packet.dst not in self.macToPort: # 3
      log.debug("Port for %s unknown -- 3:Flooding" % (packet.dst,))
      flood("Port for %s unknown -- flooding" % (packet.dst,)) # 3
    else:
      port = self.macToPort[packet.dst]
      if port == event.port: # 4
        log.debug("Same port for packet from %s -> %s on %s.%s.  4:Drop."
            % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
        drop()
        return
      # 5
      log.debug("5: Create an entry in the switch's flow table.")
      log.debug("installing flow for %s.%i -> %s.%i" %
                (packet.src, event.port, packet.dst, port))
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.idle_timeout = 10
      msg.hard_timeout = 30
      msg.actions.append(of.ofp_action_output(port = port))
      msg.data = event.ofp 
      f.write("5: Create an entry in the switch's flow table." + '\n')
      f.write('\n\n\n' + str(msg) + '\n\n')
      self.connection.send(msg)


class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self):
    core.openflow.addListeners(self)
    

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s is up" % (event.connection,))
    f.write("Connection " + str(event.connection) + " is up \n")
    LearningSwitch(event.connection)

def launch (hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning)
