package manager;

import encrypt.AESdemo;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.slf4j.LoggerFactory;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static org.apache.commons.codec.CharEncoding.UTF_8;


public class ChaincodeManager {

    private static org.slf4j.Logger log = LoggerFactory.getLogger(ChaincodeManager.class);

    private HFClient client;
    private Channel channel;
    private ChaincodeID chaincodeID;


    /**
     * Decrypt
     *
     * @param fcn
     * @param key-value
     * @return
     * @throws
     */
    public Map<String, String> invoke(String fcn, String[] userMessage) throws Exception {
        AESdemo cs = new AESdemo();
        byte[] userHash = cs.jdkSha256(userMessage[0]);
        cs.genKey(userHash);
        byte[] encontent = cs.Encrytor(userMessage[1].getBytes("UTF-8"));
        String value = new String(encontent);
        String[] args = new String[2];
        args[0]= "340221199412200415";         //暂以身份证为key，在AESdemo中新加接口，获得公钥作为key
        args[1]= value;
        Map<String, String> resultMap = new HashMap<String, String>();
        Collection<ProposalResponse> successful = new LinkedList<ProposalResponse>();
        Collection<ProposalResponse> failed = new LinkedList<ProposalResponse>();
        // Send transaction proposal to all peers
        TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeID(chaincodeID);
        transactionProposalRequest.setFcn(fcn);
        transactionProposalRequest.setArgs(args);
        Map<String, byte[]> tm2 = new HashMap<String, byte[]>();
        tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8));
        tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8));
        tm2.put("result", ":)".getBytes(UTF_8));
        transactionProposalRequest.setTransientMap(tm2);
        Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposal(transactionProposalRequest, channel.getPeers());
        for (ProposalResponse response : transactionPropResp) {
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                successful.add(response);
            } else {
                failed.add(response);
            }
        }

        Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionPropResp);
        if (proposalConsistencySets.size() != 1) {
            log.error("Expected only one set of consistent proposal responses but got " + proposalConsistencySets.size());
        }
        if (failed.size() > 0) {
            ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
            log.error("Not enough endorsers for inspect:" + failed.size() + " endorser error: " + firstTransactionProposalResponse.getMessage() + ". Was verified: "
                    + firstTransactionProposalResponse.isVerified());
            resultMap.put("code", "error");
            resultMap.put("data", firstTransactionProposalResponse.getMessage());
            return resultMap;
        } else {
            log.info("Successfully received transaction proposal responses.");
            ProposalResponse resp = transactionPropResp.iterator().next();
            byte[] x = resp.getChaincodeActionResponsePayload();
            String resultAsString = null;
            if (x != null) {
                resultAsString = new String(x, "UTF-8");
            }
            log.info("resultAsString = " + resultAsString);
            channel.sendTransaction(successful);
            resultMap.put("code", "success");
            resultMap.put("data", resultAsString);
            return resultMap;
        }
    }

    public Map<String, String> query(String fcn, String[] args) throws
            InvalidArgumentException, ProposalException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, CryptoException, TransactionException, IOException , NoSuchPaddingException
    {

        Map<String, String> resultMap = new HashMap<String, String>();
        String payload = "";
        QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
        queryByChaincodeRequest.setArgs(args);
        queryByChaincodeRequest.setFcn(fcn);
        queryByChaincodeRequest.setChaincodeID(chaincodeID);

        Map<String, byte[]> tm2 = new HashMap<String, byte[]>();
        tm2.put("HyperLedgerFabric", "QueryByChaincodeRequest:JavaSDK".getBytes(UTF_8));
        tm2.put("method", "QueryByChaincodeRequest".getBytes(UTF_8));
        queryByChaincodeRequest.setTransientMap(tm2);

        Collection<ProposalResponse> queryProposals = channel.queryByChaincode(queryByChaincodeRequest, channel.getPeers());
        for (ProposalResponse proposalResponse : queryProposals) {
            if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                log.debug("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() + ". Messages: "
                        + proposalResponse.getMessage() + ". Was verified : " + proposalResponse.isVerified());
                resultMap.put("code", "error");
                resultMap.put("data", "Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() + ". Messages: "
                        + proposalResponse.getMessage() + ". Was verified : " + proposalResponse.isVerified());
            } else {
                payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                log.debug("Query payload from peer: " + proposalResponse.getPeer().getName());
                log.debug("TransactionID: " + proposalResponse.getTransactionID());
                log.debug("" + payload);
                resultMap.put("code", "success");
                resultMap.put("data", payload);
                resultMap.put("txid", proposalResponse.getTransactionID());
            }
        }
        return resultMap;
    }
}
