#include <string>
#include <memory>
#include <time.h>

#include "temperaturesensor.h"
#include "nodemanager.h"
#include "objecttype.h"
#include "analogitem.h"
#include "dataitem.h"

using namespace std;
using namespace OpcUa;

string TemperatureSensorTypeName = "TemperatureSensorType";
NodeId TemperatureSensorTypeNodeId(1001, 1);

std::shared_ptr<AnalogItem> TemperatureSensor::s_pTemperatureInstDecl;

TemperatureSensor::TemperatureSensor(OpcUa::NodeId nodeId,
                                     OpcUa::LocalizedText browseName,
                                     OpcUa::LocalizedText displayName,
                                     OpcUa::LocalizedText description,
                                     NodeManager * pNodeManager,
                                     OpcUa::NodeId parentNode,
                                     OpcUa::NodeId parentReferenceType)
: BaseObject(nodeId, browseName, displayName, description, pNodeManager, parentNode, parentReferenceType, false)
{
    createTypes(pNodeManager);
    setType(s_pObjType->getNodeId());
    // create member Variable Temperature
    m_pTemperature = std::make_shared<AnalogItem>(s_pTemperatureInstDecl.get(),
                                                  NodeId(browseName.Text + "." + "Temperature", pNodeManager->getNamespaceIdx()),
                                                  pNodeManager,
                                                  getNodeId());
    BaseDataVariable * pTest = new BaseDataVariable(NodeId("test", pNodeManager->getNamespaceIdx()),
                                                    LocalizedText("Test"),
                                                    LocalizedText("Test"),
                                                    LocalizedText("Test"),
                                                    pNodeManager,
                                                    getNodeId(),
                                                    ObjectId::HasComponent);
}


TemperatureSensor::~TemperatureSensor()
{

}

void TemperatureSensor::setTemperature(int temperature, time_t sourceTimestamp)
{
    m_pTemperature->setValue(temperature, sourceTimestamp);
}

NodeId TemperatureSensor::getType(void)
{
    return s_pObjType->getNodeId();
}

/**
 * Initialize: create the ObjectType node in the address space
 * This is only done once: when the first TemperatureSensor object is instantiated
 * @todo Figure out a way to delete the ObjectType node from the address space
 *       when the last TemperatureSensor object is destructed
 */
void TemperatureSensor::createTypes(NodeManager * pNodeManager)
{
    // create TemperatureSensorType node (nodeclass ObjectType)
    s_pObjType = make_shared<ObjectType>(TemperatureSensorTypeNodeId,
                                         LocalizedText(TemperatureSensorTypeName),
                                         LocalizedText(TemperatureSensorTypeName),
                                         LocalizedText(TemperatureSensorTypeName),
                                         false,
                                         ObjectId::BaseObjectType,
                                         ReferenceId::HasSubtype,
                                         pNodeManager);
    // create Temperature variable instance declaration
    if(!s_pTemperatureInstDecl)
    {
        s_pTemperatureInstDecl = std::make_shared<AnalogItem>(NodeId("Temperature", pNodeManager->getNamespaceIdx()),
                                                              LocalizedText("Temperature"),
                                                              LocalizedText("Temperature"),
                                                              LocalizedText("Temperature"),
                                                              pNodeManager,
                                                              s_pObjType->getNodeId(),
                                                              ObjectId::HasComponent);
    }
}








