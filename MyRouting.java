/*******************
Team members and IDs:
Jonathan Muniz 5047584
Jeffrey Cuello 5675668
Name3 ID3
Github link:
https://github.com/Jo-Mu/MyRouting
*******************/

package net.floodlightcontroller.myrouting;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.util.ArrayList;
import java.util.Set;
import java.util.Stack;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.NodePortTuple;

import org.openflow.util.HexString;
import org.openflow.util.U8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected IDeviceService deviceProvider;
	protected ILinkDiscoveryService linkProvider;

	protected Map<Long, IOFSwitch> switches;
	protected Map<Link, LinkInfo> links;
	protected Collection<? extends IDevice> devices;

	protected static int uniqueFlow;
	protected ILinkDiscoveryService lds;
	protected IStaticFlowEntryPusherService flowPusher;
	protected boolean printedTopo = false;

	@Override
	public String getName() {
		return MyRouting.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN)
				&& (name.equals("devicemanager") || name.equals("topology")) || name
					.equals("forwarding"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ILinkDiscoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		linkProvider = context.getServiceImpl(ILinkDiscoveryService.class);
		flowPusher = context
				.getServiceImpl(IStaticFlowEntryPusherService.class);
		lds = context.getServiceImpl(ILinkDiscoveryService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		// Print the topology if not yet.
		if (!printedTopo) 
		{
			System.out.println("*** Print topology");

			Map<Long, Set<Link>> switchList = lds.getSwitchLinks();
			
			for(Map.Entry<Long, Set<Link>> entry : switchList.entrySet()) 
			{
				System.out.print("switch " + entry.getKey() + " neighbors: ");
				HashSet<Long> linkIds = new HashSet<Long>();
				
				for(Link link : entry.getValue()) 
				{
					if(entry.getKey() == link.getDst()) 
					{
						linkIds.add(link.getSrc());
					}
					else
					{
						linkIds.add(link.getDst());
					}
				}
				
				boolean firstLink = true;
				
				for(Long id : linkIds) 
				{
					if(firstLink) 
					{
						System.out.print(id);
						firstLink = false;
					}
					else 
					{
						System.out.print(", " + id);
					}
				}
				
				System.out.println();
			}

			printedTopo = true;
		}


		// eth is the packet sent by a switch and received by floodlight.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		// We process only IP packets of type 0x0800.
		if (eth.getEtherType() != 0x0800) {
			return Command.CONTINUE;
		}
		else
		{
			System.out.println("*** New flow packet");
			
			// Parse the incoming packet.
			OFPacketIn pi = (OFPacketIn)msg;
			OFMatch match = new OFMatch();
		    match.loadFromPacket(pi.getPacketData(), pi.getInPort());
			
			// Obtain source and destination IPs.
			// ...
			System.out.println("srcIP: " + match.getNetworkSourceCIDR());
	        System.out.println("dstIP: " + match.getNetworkDestinationCIDR());
	        
	        Route route = null;
	        Route revRoute = null;
	        Map<Long, Set<Link>> switch_ids = lds.getSwitchLinks();
	        
	        if (!switch_ids.isEmpty()) 
	        {
	        	Set<Long> visited = new HashSet<>();
		        Map<Long, Integer> distance = new HashMap<>();
		        Map<Long, Long> parents = new HashMap<>();        
		        List<Long> next = new ArrayList<>();
		        
		        for (Map.Entry<Long, Set<Link>> entry : switch_ids.entrySet()) 
		        {
		        	distance.put(entry.getKey(), Integer.MAX_VALUE);
		        	parents.put(entry.getKey(), entry.getKey());
		        }
		        
		        Long src_id = eth.getSourceMAC().toLong();
		        Long dst_id = eth.getDestinationMAC().toLong();
		        
		        distance.put(src_id, 0);
		        next.add(src_id);
		        
		        while (!next.isEmpty()) 
		        {
		        	if (!visited.contains(next.get(0))) 
		        	{
		        		Long node_id = next.get(0);
		        		Set<Link> neighbors = switch_ids.get(node_id);
		        		
		        		for (Link neighbor : neighbors) 
		        		{
		        			if (neighbor.getSrc() == node_id) 
		        			{
		        				if (!visited.contains(neighbor.getDst())) 
		        				{
		        					next.add(neighbor.getDst());
		        					int cost = 10 + distance.get(node_id);
		        					
		        					if (node_id % 2 == 0 && neighbor.getDst() % 2 == 0) 
		        					{
		        						cost = 100 + distance.get(node_id);
		        					}
		        					else if (node_id % 2 != 0 && neighbor.getDst() % 2 != 0) 
		        					{
		        						cost = 1 + distance.get(node_id);
		        					}
		        					
		        					int current_cost = distance.get(neighbor.getDst());
		        					if (cost < current_cost) 
		        					{
		        						parents.put(neighbor.getDst(), node_id);
		        						distance.put(neighbor.getDst(), cost);
		        					}
		        				}
		        			}
		        		}
		        		
		        		visited.add(node_id);
		        		next.remove(0);
		        	}
		        	else 
		        	{
		        		next.remove(0);
		        	}
		        }
		        
		        ArrayList<Long> revRouteList = new ArrayList<Long>();
		        boolean makingRoute = true;
		        Long nextNode = dst_id;
		        
		        while(makingRoute) 
		        {
		        	revRouteList.add(nextNode);
		        	
		        	if(parents.get(nextNode) == nextNode) 
		        	{
		        		makingRoute = false;
		        	}
		        	else 
		        	{
		        		nextNode = parents.get(nextNode);
		        	}
		        }
		        
		        Map<NodePortTuple, Set<Link>> nodePortLinks = lds.getPortLinks();
		        ArrayList<NodePortTuple> nodeRoute = new ArrayList<NodePortTuple>();
		        LinkedList<NodePortTuple> revNodeLinked = new LinkedList<NodePortTuple>();
		        System.out.print("route:");
		        
		        for(int i = revRouteList.size() - 1; i >= 0; i--) 
		        {
		        	System.out.print(" " + revRouteList.get(i));
		        	
		        	/*for(Map.Entry<NodePortTuple, Set<Link>> entry : nodePortLinks.entrySet()) 
		        	{
		        		if(entry.getKey().getNodeId() == revRouteList.get(i)) 
		        		{
		        			nodeRoute.add(entry.getKey());
		        			revNodeLinked.offerFirst(entry.getKey());
		        		}
		        	}*/
		        	
		        }
		        
		        System.out.println();
		        //ArrayList<NodePortTuple> revNodeRoute = new ArrayList<NodePortTuple>(revNodeLinked);
		        //route = new Route(new RouteId(src_id, dst_id), nodeRoute);
		        //revRoute = new Route(new RouteId(dst_id, src_id), revNodeRoute);
	        }
	        
	        // Write the path into the flow tables of the switches on the path.
	        if (route != null && revRoute != null) 
	        {
	        	installRoute(route.getPath(), match);
	        	installRoute(revRoute.getPath(), match);
	        }
	     			
	     	return Command.STOP;
		}
	}

	// Install routing rules on switches. 
	private void installRoute(List<NodePortTuple> path, OFMatch match) {

		OFMatch m = new OFMatch();

		m.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkSource(match.getNetworkSource())
				.setNetworkDestination(match.getNetworkDestination());

		for (int i = 0; i <= path.size() - 1; i += 2) {
			short inport = path.get(i).getPortId();
			m.setInputPort(inport);
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(path.get(i + 1)
					.getPortId());
			actions.add(outport);

			OFFlowMod mod = (OFFlowMod) floodlightProvider
					.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			mod.setCommand(OFFlowMod.OFPFC_ADD)
					.setIdleTimeout((short) 0)
					.setHardTimeout((short) 0)
					.setMatch(m)
					.setPriority((short) 105)
					.setActions(actions)
					.setLength(
							(short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow" + uniqueFlow, mod,
					HexString.toHexString(path.get(i).getNodeId()));
			uniqueFlow++;
		}
	}
}
