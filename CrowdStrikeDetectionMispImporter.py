from falconpy import OAuth2, Detects, IOC
from pymisp import MISPObject, MISPEvent, PyMISP
import datetime
import json
import logging
import sys
from datetime import timedelta

# Import settings from settings.py for the script.
import settings

class CrowdStrikeDetectionMispImporter:
    def __init__(self, cs_id, cs_key, cs_url, misp_url, misp_key,device_ids, confidence, severity):

        self.setup_logging()
        
        try:
            # Authenticate with CrowdStrike
            cs_auth = OAuth2(client_id=cs_id, client_secret=cs_key, base_url=cs_url)
            self.detects = Detects(cs_auth)
            self.ioc = IOC(cs_auth)

            # Connect to MISP
            self.misp = PyMISP(misp_url, misp_key, ssl=False)
            
            # Set up filtering criteria
            self.confidence = confidence
            self.severity = severity
            self.device_ids = device_ids

            self.setup_query_parameters()
        except Exception as e:
            logging.error(f"Initialization error: {e}")

    def setup_logging(self):
        logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("CrowdStrikeDetectionMispImporter initialized successfully.")
    
    def setup_query_parameters(self):
        self.time_frame = (datetime.datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d")
        self.fql_query_ = f"created_timestamp:>'{self.time_frame}'+behaviors.confidence:>{self.confidence}+behaviors.severity:>{self.severity}"
        if self.device_ids:
            self.fql_query_ += '+device.device_id:' + ','.join([f"'{device_id}'" for device_id in self.device_ids])
    
    def fetch_detections(self):
        logging.info("Fetching detections from CrowdStrike.")
        try:
            # Query CrowdStrike API for detections
            response = self.detects.query_detects(parameters={"filter": self.fql_query_})
            detection_ids = [detection for detection in response['body']['resources']]
        except Exception as e:
            logging.error(f"Error fetching detections: {e}")

        logging.info("Detections fetched successfully.")
        return detection_ids

    def get_detection_summaries(self, ids):
        logging.info(f"Retrieving detection summaries for IDs: {ids}")
        try:
            response = self.detects.get_detect_summaries(ids)
            detection_summaries = response['body']

            # Save summaries to a JSON file
            with open('detection_summaries.json', 'w') as file:
                json.dump(detection_summaries, file, ensure_ascii=False, indent=4)

        except Exception as e:
            logging.error(f"Error retrieving detection summaries: {e}")
        logging.info("Detection summaries retrieved and saved successfully.")
    
    def create_misp_event_for_detections(self):
        logging.info("Creating MISP events.")
        try:
            with open('detection_summaries.json', 'r') as file:
                detection_summaries = json.load(file)

            for detection in detection_summaries.get('resources',[]):

                # Skip if the event already exists
                event_info = detection['detection_id']
                existing_events = self.misp.search_index(eventinfo=event_info)
                if any(event['info'] == event_info for event in existing_events):
                    print(f"Event with info '{event_info}' already exists. Skipping creation.")
                    continue

                # Create MISP event
                event = MISPEvent()
                event.info = detection['detection_id']
                event.distribution = 0

                # Add device info as attributes
                device_info = detection.get('device', {})
                event.add_attribute('ip-dst', device_info['external_ip'])
                event.add_attribute('domain', device_info['hostname'])
                event_response = self.misp.add_event(event, pythonify=True)
                event_id = event_response.id
                logging.info(f"event initialized with ID: {event_id}")

                # Process each behavior
                for behavior in detection.get('behaviors', []):

                    behavior_obj = MISPObject(name="crowdstrike-behavior")

                    # Add attributes to behavior_obj
                    if behavior.get('filename'):
                        behavior_obj.add_attribute('filename', value=behavior['filename'])

                    if behavior.get('filepath'):
                        behavior_obj.add_attribute('filepath', type='other', value=behavior['filepath'])

                    if behavior.get('cmdline'):
                        behavior_obj.add_attribute('cmdline', type='text', value=behavior['cmdline'], category='Artifacts dropped')

                    if behavior.get('user_name'):
                        behavior_obj.add_attribute('user_name', type='text', value=behavior['user_name'], category='Attribution', disable_correlation=True)
                    
                    if behavior.get('description'):
                        behavior_obj.add_attribute('text', type='text', value=behavior['description'], category='Other', disable_correlation=True)
                    
                    if behavior.get('severity'):
                        behavior_obj.add_attribute('text', type='text', value=str(behavior['severity']), category='Other', disable_correlation=True)
                    
                    if behavior.get('confidence'):
                        behavior_obj.add_attribute('confidence', type='text', value=str(behavior['confidence']), category='Other', disable_correlation=True)
                    
                    if behavior.get('tactic'):
                        behavior_obj.add_attribute('tactic', type='text', value=behavior['tactic'], category='Attribution')
                    
                    if behavior.get('technique'):
                        behavior_obj.add_attribute('technique', type='text', value=behavior['technique'], category='Attribution')
                    
                    if behavior.get('display_name'):
                        behavior_obj.add_attribute('display_name', type='text', value=behavior['display_name'], category='Other')
                    
                    if behavior.get('alleged_filetype'):
                        behavior_obj.add_attribute('alleged_filetype', type='mime-type', value=behavior['alleged_filetype'], category='Payload delivery', disable_correlation=True)
                    
                    if behavior.get('scenario'):
                        behavior_obj.add_attribute('scenario', type='text', value=behavior['scenario'], category='Other', disable_correlation=True)
                    
                    if behavior.get('objective'):
                        behavior_obj.add_attribute('objective', type='text', value=behavior['objective'], category='Other')
                    
                    if behavior.get('tactic_id'):
                        behavior_obj.add_attribute('tactic_id', type='text', value=behavior['tactic_id'], category='Attribution')
                    
                    if behavior.get('technique_id'):
                        behavior_obj.add_attribute('technique_id', type='text', value=behavior['technique_id'], category='Attribution')
                    
                    if behavior.get('ioc_type'):
                        behavior_obj.add_attribute('ioc_type', type='text', value=behavior['ioc_type'], category='Other')
                    
                    if behavior.get('ioc_value'):
                        behavior_obj.add_attribute('ioc_value', type='text', value=behavior['ioc_value'], category='Other')
                    
                    if behavior.get('ioc_source'):
                        behavior_obj.add_attribute('ioc_source', type='text', value=behavior['ioc_source'], category='Other')
                    
                    if behavior.get('ioc_description'):
                        behavior_obj.add_attribute('ioc_description', type='text', value=behavior['ioc_description'], category='Other')

                    # Parent details
                    parent_details = behavior.get('parent_details', {})
                    if parent_details.get('parent_sha256'):
                        behavior_obj.add_attribute(object_relation='parent_sha256', type='sha256', value=parent_details['parent_sha256'], category='Payload delivery')
                    if parent_details.get('parent_md5'):
                        behavior_obj.add_attribute(object_relation='parent_md5', type='md5', value=parent_details['parent_md5'], category='Payload delivery')
                    if parent_details.get('parent_cmdline'):
                        behavior_obj.add_attribute(object_relation='parent_cmdline', type='text', value=parent_details['parent_cmdline'], category='Artifacts dropped')
                    if parent_details.get('parent_process_graph_id'):
                        behavior_obj.add_attribute(object_relation='parent_process_graph_id', type='text', value=parent_details['parent_process_graph_id'], category='Other')

                    self.misp.add_object(event, behavior_obj)

                # Set threat level:
                # Low(3): General mass malware.
                # Medium(2): Advanced Persistent Threats (APT)
                # High(1): Sophisticated APTs and 0day attacks.
                max_severity = detection['max_severity']
                print(max_severity)
                if max_severity <= 30:
                    event.threat_level_id = 3
                elif max_severity > 30 and max_severity <= 60:
                    event.threat_level_id = 2
                elif max_severity > 60:
                    event.threat_level_id = 1
                
                # Add your custom tags based on your specific condintions then append them to the 'tags' list.
                # tags = []

                # for tag in tags:
                #     event.add_tag(tag)
                # Update the event
                self.misp.update_event(event)

        except Exception as e:
            logging.error(f"Error creating MISP event: {e}")
        logging.info("MISP events creation completed.")

    def main(self):
        try:
            logging.info("Starting CrowdStrike to MISP import process.")
            detection_ids = self.fetch_detections()
            self.get_detection_summaries(detection_ids)
            self.create_misp_event_for_detections()
            logging.info("Import process completed.")
        except Exception as e:
            logging.error(f"Error during import process: {e}")
        
if __name__ == "__main__":
    importer = CrowdStrikeDetectionMispImporter(settings.client_id,
                                                settings.client_secret, 
                                                settings.crowdstrike_url, 
                                                settings.misp_url, 
                                                settings.misp_auth_key, 
                                                settings.device_ids,
                                                settings.confidence,
                                                settings.severity
                                                )
    importer.main()