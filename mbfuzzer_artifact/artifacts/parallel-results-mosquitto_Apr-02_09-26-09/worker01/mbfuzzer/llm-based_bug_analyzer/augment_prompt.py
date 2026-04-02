Version311 = {
    "CONNECT": """
        1. After a Network Connection is established by a Client to a Server, the first Packet sent from the Client to the Server MUST be a CONNECT Packet [MQTT-3.1.0-1]
        2. The Server MUST process a second CONNECT Packet sent from a Client as a protocol violation and disconnect the Client [MQTT-3.1.0-2]
        3. In the latter case, the Server MUST NOT continue to process the CONNECT packet in line with this specification [MQTT-3.1.2-1].
        4. The Server MUST respond to the CONNECT Packet with a CONNACK return code 0x01 (unacceptable protocol level) and then disconnect the Client if the Protocol Level is not supported by the Server [MQTT-3.1.2-2].
        5. The Server MUST validate that the reserved flag in the CONNECT Control Packet is set to zero and disconnect the Client if it is not zero [MQTT-3.1.2-3].
        6. If CleanSession is set to 1, the Client and Server MUST discard any previous Session and start a new one
        7. State data associated with this Session MUST NOT be reused in any subsequent Session [MQTT-3.1.2-6].
        8. Retained messages do not form part of the Session state in the Server, they MUST NOT be deleted when the Session ends [MQTT-3.1.2.7].
        9.  If the Will Flag is set to 1 this indicates that, if the Connect request is accepted, a Will Message MUST be stored on the Server and associated with the Network Connection
        10. The Will Message MUST be published when the Network Connection is subsequently closed unless the Will Message has been deleted by the Server on receipt of a DISCONNECT Packet [MQTT-3.1.2-8]
        11. If the Will Flag is set to 1, the Will QoS and Will Retain fields in the Connect Flags will be used by the Server, and the Will Topic and Will Message fields MUST be present in the payload [MQTT-3.1.2-9].
        12. The Will Message MUST be removed from the stored Session state in the Server once it has been published or the Server has received a DISCONNECT packet from the Client [MQTT-3.1.2-10]
        13. If the Will Flag is set to 0 the Will QoS and Will Retain fields in the Connect Flags MUST be set to zero and the Will Topic and Will Message fields MUST NOT be present in the payload [MQTT-3.1.2-11].
        14. If the Will Flag is set to 0, a Will Message MUST NOT be published when this Network Connection ends [MQTT-3.1.2-12].
        15. If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00), 1 (0x01), or 2 (0x02), It MUST NOT be 3 (0x03) [MQTT-3.1.2-14].
        16. If the Will Flag is set to 0, then the Will Retain Flag MUST be set to 0 [MQTT-3.1.2-15].
        17.  If the User Name Flag is set to 0, a user name MUST NOT be present in the payload [MQTT-3.1.2-18]
        18. If the User Name Flag is set to 1, a user name MUST be present in the payload [MQTT-3.1.2-19].
        19.  If the Password Flag is set to 0, a password MUST NOT be present in the payload [MQTT-3.1.2-20]
        20. If the Password Flag is set to 1, a password MUST be present in the payload [MQTT-3.1.2-21].
        21. If the User Name Flag is set to 0, the Password Flag MUST be set to 0 [MQTT-3.1.2-22].
        22. In the absence of sending any other Control Packets, the Client MUST send a PINGREQ Packet [MQTT-3.1.2-23].
        23. If the Keep Alive value is non-zero and the Server does not receive a Control Packet from the Client within one and a half times the Keep Alive time period, it MUST disconnect the Network Connection to the Client as if the network had failed [MQTT-3.1.2-24].
        24. These fields, if present, MUST appear in the order Client Identifier, Will Topic, Will Message, User Name, Password [MQTT-3.1.3-1].
        25. The ClientId MUST be used by Clients and by Servers to identify state that they hold relating to this MQTT Session between the Client and the Server [MQTT-3.1.3-2].
        26. The Client Identifier (ClientId) MUST be present and MUST be the first field in the CONNECT packet payload [MQTT-3.1.3-3].
        27. The ClientId MUST be a UTF-8 encoded string as defined in Section 1.5.3 [MQTT-3.1.3-4].   The Server MUST allow ClientIds which are between 1 and 23 UTF-8 encoded bytes in length, and that contain only the characters
        28. "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" [MQTT-3.1.3-5].
        29.   A Server MAY allow a Client to supply a ClientId that has a length of zero bytes, however if it does so the Server MUST treat this as a special case and assign a unique ClientId to that Client, It MUST then process the CONNECT packet as if the Client had provided that unique ClientId [MQTT-3.1.3-6]
        30.  If the Client supplies a zero-byte ClientId, the Client MUST also set CleanSession to 1 [MQTT-3.1.3-7]
        31.  If the Client supplies a zero-byte ClientId with CleanSession set to 0, the Server MUST respond to the CONNECT Packet with a CONNACK return code 0x02 (Identifier rejected) and then close the Network Connection [MQTT-3.1.3-8]
        32.  If the Server rejects the ClientId it MUST respond to the CONNECT Packet with a CONNACK return code 0x02 (Identifier rejected) and then close the Network Connection [MQTT-3.1.3-9].
        33. The Will Topic MUST be a UTF-8 encoded string as defined in Section 1.5.3 [MQTT-3.1.3-10].
        34. The User Name MUST be a UTF-8 encoded string as defined in Section 1.5.3 [MQTT-3.1.3-11]
        35. 2.     The Server MUST validate that the CONNECT Packet conforms to section 3.1 and close the Network Connection without sending a CONNACK if it does not conform [MQTT-3.1.4-1]
        36. If any of these checks fail, it SHOULD send an appropriate CONNACK response with a non-zero return code as described in section 3.2 and it MUST close the Network Connection.
        37. 1.     If the ClientId represents a Client already connected to the Server then the Server MUST disconnect the existing Client [MQTT-3.1.4-2].
        38. 2.     The Server MUST perform the processing of CleanSession that is described in section 3.1.2.4 [MQTT-3.1.4-3].
        39. 3.     The Server MUST acknowledge the CONNECT Packet with a CONNACK Packet containing a zero return code [MQTT-3.1.4-4].
        40. If the Server rejects the CONNECT, it MUST NOT process any data sent by the Client after the CONNECT Packet [MQTT-3.1.4-5]
        41. The Server MUST validate that reserved bits are set to zero and disconnect the Client if they are not zero [MQTT-3.14.1-1].
    """,
    "PUBLISH": """
        1. The DUP flag MUST be set to 1 by the Client or Server when it attempts to re-deliver a PUBLISH Packet [MQTT-3.3.1.-1]
        2. The DUP flag MUST be set to 0 for all QoS 0 messages [MQTT-3.3.1-2]
        3. The DUP flag in the outgoing PUBLISH packet is set independently to the incoming PUBLISH packet, its value MUST be determined solely by whether the outgoing PUBLISH packet is a retransmission [MQTT-3.3.1-3].
        4. A PUBLISH Packet MUST NOT have both QoS bits set to 1
        5. If a Server or Client receives a PUBLISH Packet which has both QoS bits set to 1 it MUST close the Network Connection [MQTT-3.3.1-4].
        6. If the RETAIN flag is set to 1, in a PUBLISH Packet sent by a Client to a Server, the Server MUST store the Application Message and its QoS, so that it can be delivered to future subscribers whose subscriptions match its topic name [MQTT-3.3.1-5]
        7. When a new subscription is established, the last retained message, if any, on each matching topic name MUST be sent to the subscriber [MQTT-3.3.1-6]
        8. If the Server receives a QoS 0 message with the RETAIN flag set to 1 it MUST discard any message previously retained for that topic, It SHOULD store the new QoS 0 message as the new retained message for that topic, but MAY choose to discard it at any time - if this happens there will be no retained message for that topic [MQTT-3.3.1-7]
        9. When sending a PUBLISH Packet to a Client the Server MUST set the RETAIN flag to 1 if a message is sent as a result of a new subscription being made by a Client [MQTT-3.3.1-8]
        10. It MUST set the RETAIN flag to 0 when a PUBLISH Packet is sent to a Client because it matches an established subscription regardless of how the flag was set in the message it received [MQTT-3.3.1-9]
        11. Additionally any existing retained message with the same topic name MUST be removed and any future subscribers for the topic will not receive a retained message [MQTT-3.3.1-10]
        12. A zero byte retained message MUST NOT be stored as a retained message on the Server [MQTT-3.3.1-11].
        13. If the RETAIN flag is 0, in a PUBLISH Packet sent by a Client to a Server, the Server MUST NOT store the message and MUST NOT remove or replace any existing retained message [MQTT-3.3.1-12].
        14. The Topic Name MUST be present as the first field in the PUBLISH Packet Variable header, It MUST be a UTF-8 encoded string [MQTT-3.3.2-1] as defined in section 1.5.3.
        15. The Topic Name in the PUBLISH Packet MUST NOT contain wildcard characters [MQTT-3.3.2-2].
        16. The Topic Name in a PUBLISH Packet sent by a Server to a subscribing Client MUST match the Subscriptions Topic Filter according to the matching process defined in Section 4.7 [MQTT-3.3.2-3]
        17. The receiver of a PUBLISH Packet MUST respond according to Table 3.4 - Expected Publish Packet response as determined by the QoS in the PUBLISH Packet [MQTT-3.3.4-1].
        18. If a Server implementation does not authorize a PUBLISH to be performed by a Client; it has no way of informing that Client, It MUST either make a positive acknowledgement, according to the normal QoS rules, or close the Network Connection [MQTT-3.3.5-2].
    """,
    "SUBSCRIBE": """
        1. Bits 3,2,1 and 0 of the fixed header of the SUBSCRIBE Control Packet are reserved and MUST be set to 0,0,1 and 0 respectively
        2. The Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.8.1-1].
        3. The Topic Filters in a SUBSCRIBE packet payload MUST be UTF-8 encoded strings as defined in Section 1.5.3 [MQTT-3.8.3-1]
        4. If it chooses not to support topic filters that contain wildcard characters it MUST reject any Subscription request whose filter contains them [MQTT-3.8.3-2]
        5. The payload of a SUBSCRIBE packet MUST contain at least one Topic Filter / QoS pair
        6. A SUBSCRIBE packet with no payload is a protocol violation [MQTT-3.8.3-3]
        7. The Server MUST treat a SUBSCRIBE packet as malformed and close the Network Connection if any of Reserved bits in the payload are non-zero, or QoS is not 0,1 or 2 [MQTT-3-8.3-4].
        8. When the Server receives a SUBSCRIBE Packet from a Client, the Server MUST respond with a SUBACK Packet [MQTT-3.8.4-1]
        9. The SUBACK Packet MUST have the same Packet Identifier as the SUBSCRIBE Packet that it is acknowledging [MQTT-3.8.4-2].
        10. If a Server receives a SUBSCRIBE Packet containing a Topic Filter that is identical to an existing Subscriptions Topic Filter then it MUST completely replace that existing Subscription with a new Subscription
        11. Any existing retained messages matching the Topic Filter MUST be re-sent, but the flow of publications MUST NOT be interrupted [MQTT-3.8.4-3].
        12. If a Server receives a SUBSCRIBE packet that contains multiple Topic Filters it MUST handle that packet as if it had received a sequence of multiple SUBSCRIBE packets, except that it combines their responses into a single SUBACK response [MQTT-3.8.4-4].
        13. The SUBACK Packet sent by the Server to the Client MUST contain a return code for each Topic Filter/QoS pair
        14. This return code MUST either show the maximum QoS that was granted for that Subscription or indicate that the subscription failed [MQTT-3.8.4-5]
        15. The QoS of Payload Messages sent in response to a Subscription MUST be the minimum of the QoS of the originally published message and the maximum QoS granted by the Server
        16. The server is permitted to send duplicate copies of a message to a subscriber in the case where the original message was published with QoS 1 and the maximum QoS granted was QoS 0 [MQTT-3.8.4-6].
    """,
    "SUBACK": """
        1. The order of return codes in the SUBACK Packet MUST match the order of Topic Filters in the SUBSCRIBE Packet [MQTT-3.9.3-1].
        2. SUBACK return codes other than 0x00, 0x01, 0x02 and 0x80 are reserved and MUST NOT be used [MQTT-3.9.3-2].
    """,
    "PINGREQ": """1. The Server MUST send a PINGRESP Packet in response to a PINGREQ Packet [MQTT-3.12.4-1].""",
    "PUBREL": """
        1. Bits 3,2,1 and 0 of the fixed header in the PUBREL Control Packet are reserved and MUST be set to 0,0,1 and 0 respectively
        2. The Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.6.1-1].
    """,
    "CONNACK": """
        1. The first packet sent from the Server to the Client MUST be a CONNACK Packet [MQTT-3.2.0-1].
        2. Bits 7-1 are reserved and MUST be set to 0.   Bit 0 (SP1) is the Session Present Flag. 
        3. Position: bit 0 of the Connect Acknowledge Flags.   If the Server accepts a connection with CleanSession set to 1, the Server MUST set Session Present to 0 in the CONNACK packet in addition to setting a zero return code in the CONNACK packet [MQTT-3.2.2-1]
        4. If the Server has stored Session state, it MUST set Session Present to 1 in the CONNACK packet [MQTT-3.2.2-2]
        5. If the Server does not have stored Session state, it MUST set Session Present to 0 in the CONNACK packet
        6. This is in addition to setting a zero return code in the CONNACK packet [MQTT-3.2.2-3]
        7. The Client can discard the Session state on both Client and Server by disconnecting, connecting with Clean Session set to 1 and then disconnecting again.   If a server sends a CONNACK packet containing a non-zero return code it MUST set Session Present to 0 [MQTT-3.2.2-4].
        8. If a server sends a CONNACK packet containing a non-zero return code it MUST then close the Network Connection [MQTT-3.2.2-5].
        9. If none of the return codes listed in Table 3.1  Connect Return code values are deemed applicable, then the Server MUST close the Network Connection without sending a CONNACK [MQTT-3.2.2-6].
    """,
    "UNSUBSCRIBE": """
        1. Bits 3,2,1 and 0 of the fixed header of the UNSUBSCRIBE Control Packet are reserved and MUST be set to 0,0,1 and 0 respectively
        2. The Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.10.1-1].
        3. The Topic Filters in an UNSUBSCRIBE packet MUST be UTF-8 encoded strings as defined in Section 1.5.3, packed contiguously [MQTT-3.10.3-1].
        4. The Payload of an UNSUBSCRIBE packet MUST contain at least one Topic Filter
        5. An UNSUBSCRIBE packet with no payload is a protocol violation [MQTT-3.10.3-2]
        6. The Topic Filters (whether they contain wildcards or not) supplied in an UNSUBSCRIBE packet MUST be compared character-by-character with the current set of Topic Filters held by the Server for the Client
        7. If any filter matches exactly then its owning Subscription is deleted, otherwise no additional processing occurs [MQTT-3.10.4-1].   
        8.  The Server MUST respond to an UNSUBSUBCRIBE request by sending an UNSUBACK packet
        9. The UNSUBACK Packet MUST have the same Packet Identifier as the UNSUBSCRIBE Packet [MQTT-3.10.4-4]
        10. Even where no Topic Subscriptions are deleted, the Server MUST respond with an UNSUBACK [MQTT-3.10.4-5].
        11. If a Server receives an UNSUBSCRIBE packet that contains multiple Topic Filters it MUST handle that packet as if it had received a sequence of multiple UNSUBSCRIBE packets, except that it sends just one UNSUBACK response [MQTT-3.10.4-6]. 
    """,
    "DISCONNECT": """
        1. The Server MUST validate that reserved bits are set to zero and disconnect the Client if they are not zero [MQTT-3.14.1-1].
    """
}

Version5 = {
    "AUTH": """
        1. Bits 3,2,1 and 0 of the Fixed Header of the AUTH packet are reserved and MUST all be set to 0
        2. The Client or Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.15.1-1].
        3. The sender of the AUTH Packet MUST use one of the Authenticate Reason Codes [MQTT-3.15.2-1].
        4. It is a Protocol Error to omit the Authentication Method or to include it more than once
        5. It is a Protocol Error to include Authentication Data more than once
        6. The sender MUST NOT send this property if it would increase the size of the AUTH packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.15.2-2]
        7. It is a Protocol Error to include the Reason String more than once.
        8. The sender MUST NOT send this property if it would increase the size of the AUTH packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.15.2-3]

    """,
    "PINGREQ": """1. The Server MUST send a PINGRESP packet in response to a PINGREQ packet [MQTT-3.12.4-1].""",
    "SUBACK": """
        1. The Server MUST NOT send this Property if it would increase the size of the SUBACK packet beyond the Maximum Packet Size specified by the Client [MQTT-3.9.2-1]
        2. It is a Protocol Error to include the Reason String more than once.
        3. The Server MUST NOT send this property if it would increase the size of the SUBACK packet beyond the Maximum Packet Size specified by Client [MQTT-3.9.2-2]
        4. The order of Reason Codes in the SUBACK packet MUST match the order of Topic Filters in the SUBSCRIBE packet [MQTT-3.9.3-1].
        5. The Server sending a SUBACK packet MUST use one of the Subscribe Reason Codes for each Topic Filter received [MQTT-3.9.3-2].
    """,
    "SUBSCRIBE": """
        1. Bits 3,2,1 and 0 of the Fixed Header of the SUBSCRIBE packet are reserved and MUST be set to 0,0,1 and 0 respectively
        2. It is a Protocol Error if the Subscription Identifier has a value of 0, It is a Protocol Error to include the Subscription Identifier more than once.
        3. The Topic Filters MUST be a UTF-8 Encoded String [MQTT-3.8.3-1]
        4. The Payload MUST contain at least one Topic Filter and Subscription Options pair [MQTT-3.8.3-2]
        5. If the value is 1, Application Messages MUST NOT be forwarded to a connection with a ClientID equal to the ClientID of the publishing connection [MQTT-3.8.3-3]
        6. It is a Protocol Error to send a Retain Handling value of 3.
        7. The Server MUST treat a SUBSCRIBE packet as malformed if any of Reserved bits in the Payload are non-zero [MQTT-3.8.3-5].
        8. When the Server receives a SUBSCRIBE packet from a Client, the Server MUST respond with a SUBACK packet [MQTT-3.8.4-1]
        9. The SUBACK packet MUST have the same Packet Identifier as the SUBSCRIBE packet that it is acknowledging [MQTT-3.8.4-2].
        10. If a Server receives a SUBSCRIBE packet containing a Topic Filter that is identical to a Non‑shared Subscriptions Topic Filter for the current Session, then it MUST replace that existing Subscription with a new Subscription [MQTT-3.8.4-3]
        11. If the Retain Handling option is 0, any existing retained messages matching the Topic Filter MUST be re-sent, but Applicaton Messages MUST NOT be lost due to replacing the Subscription [MQTT-3.8.4-4]
        12. If a Server receives a SUBSCRIBE packet that contains multiple Topic Filters it MUST handle that packet as if it had received a sequence of multiple SUBSCRIBE packets, except that it combines their responses into a single SUBACK response [MQTT-3.8.4-5].
        13. The SUBACK packet sent by the Server to the Client MUST contain a Reason Code for each Topic Filter/Subscription Option pair [MQTT-3.8.4-6]
        14. This Reason Code MUST either show the maximum QoS that was granted for that Subscription or indicate that the subscription failed [MQTT-3.8.4-7]
        15. The QoS of Application Messages sent in response to a Subscription MUST be the minimum of the QoS of the originally published message and the Maximum QoS granted by the Server [MQTT-3.8.4-8]
        16. The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name [MQTT-4.7.0-1].
        17. The Server MUST NOT match Topic Filters starting with a wildcard character (# or +) with Topic Names beginning with a $ character [MQTT-4.7.2-1]
        18. All Topic Names and Topic Filters MUST be at least one character long [MQTT-4.7.3-1]
        19. Topic Names and Topic Filters MUST NOT include the null character (Unicode U+0000) [Unicode] [MQTT-4.7.3-2]
        20. Topic Names and Topic Filters are UTF-8 Encoded Strings; they MUST NOT encode to more than 65,535 bytes [MQTT-4.7.3-3]
        21. When it performs subscription matching the Server MUST NOT perform any normalization of Topic Names or Topic Filters, or any modification or substitution of unrecognized characters [MQTT-4.7.3-4]
        22. The single-level wildcard can be used at any level in the Topic Filter, including first and last levels. Where it is used it MUST occupy an entire level of the filter [MQTT-4.7.1-3]  
        23. The multi-level wildcard character MUST be specified either on its own or following a topic level separator. In either case it MUST be the last character specified in the Topic Filter [MQTT-4.7.1-2].
        24. It is a Protocol Error to set the No Local bit to 1 on a Shared Subscription [MQTT-3.8.3-4].
    """,
    "PUBCOMP": """
        1. The Client or Server sending the PUBCOMP packet MUST use one of the PUBCOMP Reason Code values [MQTT-3.7.2-1]
        2. The sender MUST NOT send this Property if it would increase the size of the PUBCOMP packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.7.2-2]
        3. It is a Protocol Error to include the Reason String more than once.
        4. The sender MUST NOT send this property if it would increase the size of the PUBCOMP packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.7.2-3]
    """,
    "PUBREL": """
        1. Bits 3,2,1 and 0 of the Fixed Header in the PUBREL packet are reserved and MUST be set to 0,0,1 and 0 respectively
        2. The Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.6.1-1].
        3. The Client or Server sending the PUBREL packet MUST use one of the PUBREL Reason Code values [MQTT-3.6.2-1]
        4. The sender MUST NOT send this Property if it would increase the size of the PUBREL packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.6.2-2]
        5. It is a Protocol Error to include the Reason String more than once.
        6. The sender MUST NOT send this property if it would increase the size of the PUBREL packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.6.2-3]
    """,
    "PUBREC": """
        1. The Client or Server sending the PUBREC packet MUST use one of the PUBREC Reason Code values [MQTT-3.5.2-1]
        2. The sender MUST NOT send this property if it would increase the size of the PUBREC packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.5.2-2]
        3. It is a Protocol Error to include the Reason String more than once.
        4. The sender MUST NOT send this property if it would increase the size of the PUBREC packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.5.2-3]
    """,
    "PUBACK": """
        1. The Client or Server sending the PUBACK packet MUST use one of the PUBACK Reason Codes [MQTT-3.4.2-1]
        2. The sender MUST NOT send this property if it would increase the size of the PUBACK packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.4.2-2]
        3. It is a Protocol Error to include the Reason String more than once.
        4. The sender MUST NOT send this property if it would increase the size of the PUBACK packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.4.2-3]
    """,
    "PUBLISH": """
        1. The DUP flag MUST be set to 1 by the Client or Server when it attempts to re-deliver a PUBLISH packet [MQTT-3.3.1-1]
        2. The DUP flag MUST be set to 0 for all QoS 0 messages [MQTT-3.3.1-2]
        3. The DUP flag in the outgoing PUBLISH packet is set independently to the incoming PUBLISH packet, its value MUST be determined solely by whether the outgoing PUBLISH packet is a retransmission [MQTT-3.3.1-3].
        4. A PUBLISH Packet MUST NOT have both QoS bits set to 1 [MQTT-3.3.1-4]
        5. If the RETAIN flag is set to 1 in a PUBLISH packet sent by a Client to a Server, the Server MUST replace any existing retained message for this topic and store the Application Message [MQTT-3.3.1-5], so that it can be delivered to future subscribers whose subscriptions match its Topic Name
        6. If the Payload contains zero bytes it is processed normally by the Server but any retained message with the same topic name MUST be removed and any future subscribers for the topic will not receive a retained message [MQTT-3.3.1-6]
        7. A retained message with a Payload containing zero bytes MUST NOT be stored as a retained message on the Server [MQTT-3.3.1-7].
        8. If the RETAIN flag is 0 in a PUBLISH packet sent by a Client to a Server, the Server MUST NOT store the message as a retained message and MUST NOT remove or replace any existing retained message [MQTT-3.3.1-8].
        9. The Topic Name MUST be present as the first field in the PUBLISH packet Variable Header, It MUST be a UTF-8 Encoded String as defined in section 1.5.4 [MQTT-3.3.2-1].
        10. The Topic Name in the PUBLISH packet MUST NOT contain wildcard characters [MQTT-3.3.2-2].
        11. The Topic Name in a PUBLISH packet sent by a Server to a subscribing Client MUST match the Subscriptions Topic Filter according to the matching process defined in section 4.7 [MQTT-3.3.2-3]
        12. A Server MUST send the Payload Format Indicator unaltered to all subscribers receiving the Application Message [MQTT-3.3.2-4]
        13. If the Message Expiry Interval has passed and the Server has not managed to start onward delivery to a matching subscriber, then it MUST delete the copy of the message for that subscriber [MQTT-3.3.2-5].
        14. Followed by the Two Byte integer representing the Topic Alias value, It is a Protocol Error to include the Topic Alias value more than once.
        15. A receiver MUST NOT carry forward any Topic Alias mappings from one Network Connection to another [MQTT-3.3.2-7].
        16. A sender MUST NOT send a PUBLISH packet containing a Topic Alias which has the value 0 [MQTT-3.3.2-8].
        17. A Client MUST NOT send a PUBLISH packet with a Topic Alias greater than the Topic Alias Maximum value returned by the Server in the CONNACK packet [MQTT-3.3.2-9]
        18. A Client MUST accept all Topic Alias values greater than 0 and less than or equal to the Topic Alias Maximum value that it sent in the CONNECT packet [MQTT-3.3.2-10]
        19. A Server MUST NOT send a PUBLISH packet with a Topic Alias greater than the Topic Alias Maximum value sent by the Client in the CONNECT packet [MQTT-3.3.2-11]
        20. A Server MUST accept all Topic Alias values greater than 0 and less than or equal to the Topic Alias Maximum value that it returned in the CONNACK packet [MQTT-3.3.2-12]
        21. The Response Topic MUST be a UTF-8 Encoded String as defined in section 1.5.4 [MQTT-3.3.2-13]
        22. The Response Topic MUST NOT contain wildcard characters [MQTT-3.3.2-14]
        23. It is a Protocol Error to include the Response Topic more than once
        24. The Correlation Data is used by the sender of the Request Message to identify which request the Response Message is for when it is received, It is a Protocol Error to include Correlation Data more than once
        25. The Server MUST send the Correlation Data unaltered to all subscribers receiving the Application Message [MQTT-3.3.2-16]
        26. The Server MUST send all User Properties unaltered in a PUBLISH packet when forwarding the Application Message to a Client [MQTT-3.3.2-17]
        27. The Server MUST maintain the order of User Properties when forwarding the Application Message [MQTT-3.3.2-18].
        28. A Server MUST send the Content Type unaltered to all subscribers receiving the Application Message [MQTT-3.3.2-20]
        29. The receiver of a PUBLISH Packet MUST respond with the packet as determined by the QoS in the PUBLISH Packet [MQTT-3.3.4-1].
        30. In this case the Server MUST deliver the message to the Client respecting the maximum QoS of all the matching subscriptions [MQTT-3.3.4-2]
        31. If the Client specified a Subscription Identifier for any of the overlapping subscriptions the Server MUST send those Subscription Identifiers in the message which is published as the result of the subscriptions [MQTT-3.3.4-3]
        32. If the Server sends a single copy of the message it MUST include in the PUBLISH packet the Subscription Identifiers for all matching subscriptions which have a Subscription Identifiers, their order is not significant [MQTT-3.3.4-4]
        33. If the Server sends multiple PUBLISH packets it MUST send, in each of them, the Subscription Identifier of the matching subscription if it has a Subscription Identifier [MQTT-3.3.4-5].
        34. A PUBLISH packet sent from a Client to a Server MUST NOT contain a Subscription Identifier [MQTT-3.3.4-6].
        35. The Client MUST NOT send more than Receive Maximum QoS 1 and QoS 2 PUBLISH packets for which it has not received PUBACK, PUBCOMP, or PUBREC with a Reason Code of 128 or greater from the Server [MQTT-3.3.4-7]
        36. The Client MUST NOT delay the sending of any packets other than PUBLISH packets due to having sent Receive Maximum PUBLISH packets without receiving acknowledgements for them [MQTT-3.3.4-8]
        37. The Server MUST NOT send more than Receive Maximum QoS 1 and QoS 2 PUBLISH packets for which it has not received PUBACK, PUBCOMP, or PUBREC with a Reason Code of 128 or greater from the Client [MQTT-3.3.4-9]
        38. The Server MUST NOT delay the sending of any packets other than PUBLISH packets due to having sent Receive Maximum PUBLISH packets without receiving acknowledgements for them [MQTT-3.3.4-10]
        39. The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name [MQTT-4.7.0-1].
        40. The Server MUST NOT match Topic Filters starting with a wildcard character (# or +) with Topic Names beginning with a $ character [MQTT-4.7.2-1]
        41. All Topic Names and Topic Filters MUST be at least one character long [MQTT-4.7.3-1]
        42. Topic Names and Topic Filters MUST NOT include the null character (Unicode U+0000) [Unicode] [MQTT-4.7.3-2]
        43. Topic Names and Topic Filters are UTF-8 Encoded Strings; they MUST NOT encode to more than 65,535 bytes [MQTT-4.7.3-3]
        44. When it performs subscription matching the Server MUST NOT perform any normalization of Topic Names or Topic Filters, or any modification or substitution of unrecognized characters [MQTT-4.7.3-4]
    """,
    "CONNACK": """
        1. The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than AUTH [MQTT-3.2.0-1]
        2. The Server MUST NOT send more than one CONNACK in a Network Connection [MQTT-3.2.0-2].
        3. Bits 7-1 are reserved and MUST be set to 0 [MQTT-3.2.2-1].
        4. If the Server accepts a connection with Clean Start set to 1, the Server MUST set Session Present to 0 in the CONNACK packet in addition to setting a 0x00 (Success) Reason Code in the CONNACK packet [MQTT-3.2.2-2].
        5. If the Server accepts a connection with Clean Start set to 0 and the Server has Session State for the ClientID, it MUST set Session Present to 1 in the CONNACK packet, otherwise it MUST set Session Present to 0 in the CONNACK packet
        6. In both cases it MUST set a 0x00 (Success) Reason Code in the CONNACK packet [MQTT-3.2.2-3].
        7. If a Server sends a CONNACK packet containing a non-zero Reason Code it MUST set Session Present to 0 [MQTT-3.2.2-6].
        8. If a Server sends a CONNACK packet containing a Reason code of 128 or greater it MUST then close the Network Connection [MQTT-3.2.2-7].
        9. Followed by a Byte with a value of either 0 or 1, It is a Protocol Error to include Maximum QoS more than once, or to have a value other than 0 or 1
        10. If a Server does not support QoS 1 or QoS 2 PUBLISH packets it MUST send a Maximum QoS in the CONNACK packet specifying the highest QoS it supports [MQTT-3.2.2-9]
        11. A Server that does not support QoS 1 or QoS 2 PUBLISH packets MUST still accept SUBSCRIBE packets containing a Requested QoS of 0, 1 or 2 [MQTT-3.2.2-10].
        12. If a Client receives a Maximum QoS from a Server, it MUST NOT send PUBLISH packets at a QoS level exceeding the Maximum QoS level specified [MQTT-3.2.2-11]
        13. If not present, then retained messages are supported, It is a Protocol Error to include Retain Available more than once or to use a value other than 0 or 1.
        14. If a Server receives a CONNECT packet containing a Will Message with the Will Retain set to 1, and it does not support retained messages, the Server MUST reject the connection request, It SHOULD send CONNACK with Reason Code 0x9A (Retain not supported) and then it MUST close the Network Connection [MQTT-3.2.2-13]
        15. , It is a Protocol Error to include the Maximum Packet Size more than once, or for the value to be set to zero.
        16. Followed by the UTF-8 string which is the Assigned Client Identifier, It is a Protocol Error to include the Assigned Client Identifier more than once.
        17. If the Client connects using a zero length Client Identifier, the Server MUST respond with a CONNACK containing an Assigned Client Identifier
        18. Followed by the Two Byte Integer representing the Topic Alias Maximum value, It is a Protocol Error to include the Topic Alias Maximum value more than once
        19. The Client MUST NOT send a Topic Alias in a PUBLISH packet to the Server greater than this value [MQTT-3.2.2-17]
        20. If Topic Alias Maximum is absent or 0, the Client MUST NOT send any Topic Aliases on to the Server [MQTT-3.2.2-18].
        21. The Server MUST NOT send this property if it would increase the size of the CONNACK packet beyond the Maximum Packet Size specified by the Client [MQTT-3.2.2-19]
        22. If not present, then Shared Subscriptions are supported, It is a Protocol Error to include the Shared Subscription Available more than once or to send a value other than 0 or 1.
        23. If the Server sends a Server Keep Alive on the CONNACK packet, the Client MUST use this value instead of the Keep Alive value the Client sent on CONNECT [MQTT-3.2.2-21]
        24. If the Server does not send the Server Keep Alive, the Server MUST use the Keep Alive value set by the Client on CONNECT [MQTT-3.2.2-22]
        25. The contents of this data are defined by the authentication method and the state of already exchanged authentication data, It is a Protocol Error to include the Authentication Data more than once
    """,
    "CONNECT": """
        1. After a Network Connection is established by a Client to a Server, the first packet sent from the Client to the Server MUST be a CONNECT packet [MQTT-3.1.0-1].
        2. The Server MUST process a second CONNECT packet sent from a Client as a Protocol Error and close the Network Connection [MQTT-3.1.0-2]
        3. The protocol name MUST be the UTF-8 String "MQTT"
        4. If the Server does not want to accept the CONNECT, and wishes to reveal that it is an MQTT Server it MAY send a CONNACK packet with Reason Code of 0x84 (Unsupported Protocol Version), and then it MUST close the Network Connection [MQTT-3.1.2-1].
        5. If the Protocol Version is not 5 and the Server does not want to accept the CONNECT packet, the Server MAY send a CONNACK packet with Reason Code 0x84 (Unsupported Protocol Version) and then MUST close the Network Connection [MQTT-3.1.2-2].
        6. The Server MUST validate that the reserved flag in the CONNECT packet is set to 0 [MQTT-3.1.2-3]
        7. If a CONNECT packet is received with Clean Start is set to 1, the Client and Server MUST discard any existing Session and start a new Session [MQTT-3.1.2-4]
        8. If a CONNECT packet is received with Clean Start set to 0 and there is a Session associated with the Client Identifier, the Server MUST resume communications with the Client based on state from the existing Session [MQTT-3.1.2-5]
        9. If a CONNECT packet is received with Clean Start set to 0 and there is no Session associated with the Client Identifier, the Server MUST create a new Session [MQTT-3.1.2-6].
        10. If the Will Flag is set to 1 this indicates that a Will Message MUST be stored on the Server and associated with the Session [MQTT-3.1.2-7]
        11. The Will Message MUST be published after the Network Connection is subsequently closed and either the Will Delay Interval has elapsed or the Session ends, unless the Will Message has been deleted by the Server on receipt of a DISCONNECT packet with Reason Code 0x00 (Normal disconnection) or a new Network Connection for the ClientID is opened before the Will Delay Interval has elapsed [MQTT-3.1.2-8]
        12. If the Will Flag is set to 1, the Will Properties, Will Topic, and Will Payload fields MUST be present in the Payload [MQTT-3.1.2-9]
        13. The Will Message MUST be removed from the stored Session State in the Server once it has been published or the Server has received a DISCONNECT packet with a Reason Code of 0x00 (Normal disconnection) from the Client [MQTT-3.1.2-10]
        14. If the Will Flag is set to 0, then the Will QoS MUST be set to 0 (0x00) [MQTT-3.1.2-11].
        15. If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00), 1 (0x01), or 2 (0x02) [MQTT-3.1.2-12]
        16. If the Will Flag is set to 0, then Will Retain MUST be set to 0 [MQTT-3.1.2-13]
        17. If the Will Flag is set to 1 and Will Retain is set to 0, the Server MUST publish the Will Message as a non-retained message [MQTT-3.1.2-14]
        18. If the Will Flag is set to 1 and Will Retain is set to 1, the Server MUST publish the Will Message as a retained message [MQTT-3.1.2-15].
        19. If the User Name Flag is set to 0, a User Name MUST NOT be present in the Payload [MQTT-3.1.2-16]
        20. If the User Name Flag is set to 1, a User Name MUST be present in the Payload [MQTT-3.1.2-17].
        21. If the Password Flag is set to 0, a Password MUST NOT be present in the Payload [MQTT-3.1.2-18]
        22. If the Password Flag is set to 1, a Password MUST be present in the Payload [MQTT-3.1.2-19].
        23. If Keep Alive is non-zero and in the absence of sending any other MQTT Control Packets, the Client MUST send a PINGREQ packet [MQTT-3.1.2-20].
        24. If the Server returns a Server Keep Alive on the CONNACK packet, the Client MUST use that value instead of the value it sent as the Keep Alive [MQTT-3.1.2-21].
        25. If the Keep Alive value is non-zero and the Server does not receive an MQTT Control Packet from the Client within one and a half times the Keep Alive time period, it MUST close the Network Connection to the Client as if the network had failed [MQTT-3.1.2-22].
        26. It is a Protocol Error to include the Session Expiry Interval more than once.
        27. The Client and Server MUST store the Session State after the Network Connection is closed if the Session Expiry Interval is greater than 0 [MQTT-3.1.2-23].
        28. It is a Protocol Error to include the Receive Maximum value more than once or for it to have the value 0.
        29. It is a Protocol Error to include the Maximum Packet Size more than once, or for the value to be set to zero.
        30. The Server MUST NOT send packets exceeding Maximum Packet Size to the Client [MQTT-3.1.2-24]
        31. Where a Packet is too large to send, the Server MUST discard it without sending it and then behave as if it had completed sending that Application Message [MQTT-3.1.2-25]
        32. It is a Protocol Error to include the Topic Alias Maximum value more than once
        33. The Server MUST NOT send a Topic Alias in a PUBLISH packet to the Client greater than Topic Alias Maximum [MQTT-3.1.2-26]
        34. If Topic Alias Maximum is absent or zero, the Server MUST NOT send any Topic Aliases to the Client [MQTT-3.1.2-27].
        35. It is Protocol Error to include the Request Response Information more than once, or to have a value other than 0 or 1
        36. A value of 0 indicates that the Server MUST NOT return Response Information [MQTT-3.1.2-28]
        37. It is a Protocol Error to include Request Problem Information more than once, or to have a value other than 0 or 1
        38. If the value of Request Problem Information is 0, the Server MAY return a Reason String or User Properties on a CONNACK or DISCONNECT packet, but MUST NOT send a Reason String or User Properties on any packet other than PUBLISH, CONNACK, or DISCONNECT [MQTT-3.1.2-29]
        39. Followed by a UTF-8 Encoded String containing the name of the authentication method used for extended authentication .It is a Protocol Error to include Authentication Method more than once.
        40. If a Client sets an Authentication Method in the CONNECT, the Client MUST NOT send any packets other than AUTH or DISCONNECT packets until it has received a CONNACK packet [MQTT-3.1.2-30].
        41. It is a Protocol Error to include Authentication Data if there is no Authentication Method
        42. It is a Protocol Error to include Authentication Data more than once
        43. These fields, if present, MUST appear in the order Client Identifier, Will Properties, Will Topic, Will Payload, User Name, Password [MQTT-3.1.3-1].
        44. The ClientID MUST be used by Clients and by Servers to identify state that they hold relating to this MQTT Session between the Client and the Server [MQTT-3.1.3-2]
        45. The ClientID MUST be present and is the first field in the CONNECT packet Payload [MQTT-3.1.3-3].
        46. The ClientID MUST be a UTF-8 Encoded String as defined in section 1.5.4 [MQTT-3.1.3-4].
        47. The Server MUST allow ClientIDs which are between 1 and 23 UTF-8 encoded bytes in length, and that contain only the characters
        48. "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" [MQTT-3.1.3-5].
        49. A Server MAY allow a Client to supply a ClientID that has a length of zero bytes, however if it does so the Server MUST treat this as a special case and assign a unique ClientID to that Client [MQTT-3.1.3-6]
        50. It MUST then process the CONNECT packet as if the Client had provided that unique ClientID, and MUST return the Assigned Client Identifier in the CONNACK packet [MQTT-3.1.3-7].
        51. If the Server rejects the ClientID it MAY respond to the CONNECT packet with a CONNACK using Reason Code 0x85 (Client Identifier not valid) as described in section 4.13 Handling errors, and then it MUST close the Network Connection [MQTT-3.1.3-8].
        52. It is a Protocol Error to include the Will Delay Interval more than once
        53. If a new Network Connection to this Session is made before the Will Delay Interval has passed, the Server MUST NOT send the Will Message [MQTT-3.1.3-9].
        54. It is a Protocol Error to include the Payload Format Indicator more than once
        55. It is a Protocol Error to include the Message Expiry Interval more than once.
        56. It is a Protocol Error to include the Content Type more than once
        57. It is a Protocol Error to include the Response Topic more than once
        58. It is a Protocol Error to include Correlation Data more than once
        59. The Server MUST maintain the order of User Properties when publishing the Will Message [MQTT-3.1.3-10].
        60. The Will Topic MUST be a UTF-8 Encoded String as defined in section 1.5.4 [MQTT-3.1.3-11].
        61. The User Name MUST be a UTF-8 Encoded String as defined in section 1.5.4 [MQTT-3.1.3-12]
        62. 2.     The Server MUST validate that the CONNECT packet matches the format described in section 3.1 and close the Network Connection if it does not match [MQTT-3.1.4-1]
        63. 1.     If the ClientID represents a Client already connected to the Server, the Server sends a DISCONNECT packet to the existing Client with Reason Code of 0x8E (Session taken over) as described in section 4.13 and MUST close the Network Connection of the existing Client [MQTT-3.1.4-3]
        64. 2.     The Server MUST perform the processing of Clean Start that is described in section 3.1.2.4 [MQTT-3.1.4-4].
        65. 3.     The Server MUST acknowledge the CONNECT packet with a CONNACK packet containing a 0x00 (Success) Reason Code [MQTT-3.1.4-5].
        66. If the Server rejects the CONNECT, it MUST NOT process any data sent by the Client after the CONNECT packet except AUTH packets [MQTT-3.1.4-6].
        67. A Server MUST NOT send a DISCONNECT until after it has sent a CONNACK with Reason Code of less than 0x80 [MQTT-3.14.0-1].
        68. The Client or Server MUST validate that reserved bits are set to 0, the Server MUST validate that the reserved flag in the CONNECT packet is set to 0 [MQTT-3.1.2-3].
        69. If they are not zero it sends a DISCONNECT packet with a Reason code of 0x81 (Malformed Packet) as described in section 4.13 [MQTT-3.14.1-1].
        70. The Client or Server sending the DISCONNECT packet MUST use one of the DISCONNECT Reason Code values [MQTT-3.14.2-1]
        71. It is a Protocol Error to include the Session Expiry Interval more than once.
        72. The Session Expiry Interval MUST NOT be sent on a DISCONNECT by the Server [MQTT-3.14.2-2].
        73. The sender MUST NOT send this Property if it would increase the size of the DISCONNECT packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.14.2-3]
        74. It is a Protocol Error to include the Reason String more than once.
        75. The sender MUST NOT send this property if it would increase the size of the DISCONNECT packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.14.2-4]
        76. It is a Protocol Error to include the Server Reference more than once.
    """,
    "DISCONNECT": """
        1. A Server MUST NOT send a DISCONNECT until after it has sent a CONNACK with Reason Code of less than 0x80 [MQTT-3.14.0-1].
        2. The Client or Server MUST validate that reserved bits are set to 0
        3. If they are not zero it sends a DISCONNECT packet with a Reason code of 0x81 (Malformed Packet) as described in section 4.13 [MQTT-3.14.1-1].
        4. Followed by the Four Byte Integer representing the Session Expiry Interval in seconds, It is a Protocol Error to include the Session Expiry Interval more than once.
        5. The Session Expiry Interval MUST NOT be sent on a DISCONNECT by the Server [MQTT-3.14.2-2].
        6. The sender MUST NOT send this Property if it would increase the size of the DISCONNECT packet beyond the Maximum Packet Size specified by the receiver [MQTT-3.14.2-3]
        7. It is a Protocol Error to include the Reason String more than once.
        8. Followed by a UTF-8 Encoded String which can be used by the Client to identify another Server to use, It is a Protocol Error to include the Server Reference more than once.
    """,
    "UNSUBACK": """
        1. The Server MUST NOT send this Property if it would increase the size of the UNSUBACK packet beyond the Maximum Packet Size specified by the Client [MQTT-3.11.2-1]
        2. It is a Protocol Error to include the Reason String more than once.
        3. The Server MUST NOT send this property if it would increase the size of the UNSUBACK packet beyond the Maximum Packet Size specified by the Client [MQTT-3.11.2-2]
        4. The order of Reason Codes in the UNSUBACK packet MUST match the order of Topic Filters in the UNSUBSCRIBE packet [MQTT-3.11.3-1].
        5. The Server sending an UNSUBACK packet MUST use one of the Unsubscribe Reason Code values for each Topic Filter received [MQTT-3.11.3-2].
    """,
    "UNSUBSCRIBE": """
        1. Bits 3,2,1 and 0 of the Fixed Header of the UNSUBSCRIBE packet are reserved and MUST be set to 0,0,1 and 0 respectively
        2. The Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.10.1-1].
        3. The Topic Filters in an UNSUBSCRIBE packet MUST be UTF-8 Encoded Strings [MQTT-3.10.3-1] as defined in section 1.5.4, packed contiguously.
        4. The Payload of an UNSUBSCRIBE packet MUST contain at least one Topic Filter [MQTT-3.10.3-2]
        5. The Topic Filters (whether they contain wildcards or not) supplied in an UNSUBSCRIBE packet MUST be compared character-by-character with the current set of Topic Filters held by the Server for the Client
        6. If any filter matches exactly then its owning Subscription MUST be deleted [MQTT-3.10.4-1], otherwise no additional processing occurs.
        7. The Server MUST respond to an UNSUBSCRIBE request by sending an UNSUBACK packet [MQTT-3.10.4-4]
        8. The UNSUBACK packet MUST have the same Packet Identifier as the UNSUBSCRIBE packet
        9. Even where no Topic Subscriptions are deleted, the Server MUST respond with an UNSUBACK [MQTT-3.10.4-5].
        10. If a Server receives an UNSUBSCRIBE packet that contains multiple Topic Filters, it MUST process that packet as if it had received a sequence of multiple UNSUBSCRIBE packets, except that it sends just one UNSUBACK response [MQTT-3.10.4-6].
        11. The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name [MQTT-4.7.0-1].
        12. The single-level wildcard can be used at any level in the Topic Filter, including first and last levels. Where it is used it MUST occupy an entire level of the filter [MQTT-4.7.1-3]
        13. The multi-level wildcard character MUST be specified either on its own or following a topic level separator. In either case it MUST be the last character specified in the Topic Filter [MQTT-4.7.1-2].
        14. All Topic Names and Topic Filters MUST be at least one character long [MQTT-4.7.3-1]
        15. Topic Names and Topic Filters MUST NOT include the null character (Unicode U+0000) [Unicode] [MQTT-4.7.3-2]
        16. Topic Names and Topic Filters are UTF-8 Encoded Strings; they MUST NOT encode to more than 65,535 bytes [MQTT-4.7.3-3]
    """,

}