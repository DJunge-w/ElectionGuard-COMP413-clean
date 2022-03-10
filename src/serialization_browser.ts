/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/**
 * Compared to serialization.ts, this is a browser friendly edition where node module like fs are not required
 * Thus, it also lack some of the fs supported features.
 */
import {CiphertextBallot,
  PlaintextBallot} from "./simple_election_data";
import {plainToClass} from "class-transformer";
import {Manifest} from "./manifest";
import { ElementModQ } from "./group";

const json_string = "{\n" +
  "    \"object_id\": \"some-external-id-string-123\",\n" +
  "    \"style_id\": \"jefferson-county-ballot-style\",\n" +
  "    \"manifest_hash\": \"26F5\",\n" +
  "    \"code_seed\": \"CD2B\",\n" +
  "    \"contests\": [\n" +
  "        {\n" +
  "            \"object_id\": \"justice-supreme-court\",\n" +
  "            \"sequence_order\": \"00\",\n" +
  "            \"description_hash\": \"6654\",\n" +
  "            \"ballot_selections\": [\n" +
  "                {\n" +
  "                    \"object_id\": \"john-adams-selection\",\n" +
  "                    \"sequence_order\": \"00\",\n" +
  "                    \"description_hash\": \"2DFF\",\n" +
  "                    \"ciphertext\": {\n" +
  "                        \"pad\": \"15432452611067669264\",\n" +
  "                        \"data\": \"15616222367556762890\"\n" +
  "                    },\n" +
  "                    \"crypto_hash\": \"85F9\",\n" +
  "                    \"is_placeholder_selection\": \"00\",\n" +
  "                    \"nonce\": \"3298\",\n" +
  "                    \"proof\": {\n" +
  "                        \"proof_zero_pad\": \"8442157498440623226\",\n" +
  "                        \"proof_zero_data\": \"18335962429120460393\",\n" +
  "                        \"proof_one_pad\": \"15711130229203582655\",\n" +
  "                        \"proof_one_data\": \"17487616188833869553\",\n" +
  "                        \"proof_zero_challenge\": \"4510\",\n" +
  "                        \"proof_one_challenge\": \"976A\",\n" +
  "                        \"challenge\": \"DC7A\",\n" +
  "                        \"proof_zero_response\": \"4E8A\",\n" +
  "                        \"proof_one_response\": \"3B18\",\n" +
  "                        \"usage\": \"Prove selection's value (0 or 1)\"\n" +
  "                    },\n" +
  "                    \"extended_data\": null\n" +
  "                },\n" +
  "                {\n" +
  "                    \"object_id\": \"benjamin-franklin-selection\",\n" +
  "                    \"sequence_order\": \"01\",\n" +
  "                    \"description_hash\": \"C9D7\",\n" +
  "                    \"ciphertext\": {\n" +
  "                        \"pad\": \"11884679765322039846\",\n" +
  "                        \"data\": \"3504487674681685196\"\n" +
  "                    },\n" +
  "                    \"crypto_hash\": \"CD4C\",\n" +
  "                    \"is_placeholder_selection\": \"00\",\n" +
  "                    \"nonce\": \"BDE6\",\n" +
  "                    \"proof\": {\n" +
  "                        \"proof_zero_pad\": \"6681702374317616247\",\n" +
  "                        \"proof_zero_data\": \"5919121084903920119\",\n" +
  "                        \"proof_one_pad\": \"6490626824174500658\",\n" +
  "                        \"proof_one_data\": \"13415779466211002491\",\n" +
  "                        \"proof_zero_challenge\": \"95CB\",\n" +
  "                        \"proof_one_challenge\": \"A97A\",\n" +
  "                        \"challenge\": \"3F54\",\n" +
  "                        \"proof_zero_response\": \"7681\",\n" +
  "                        \"proof_one_response\": \"0C33\",\n" +
  "                        \"usage\": \"Prove selection's value (0 or 1)\"\n" +
  "                    },\n" +
  "                    \"extended_data\": null\n" +
  "                },\n" +
  "                {\n" +
  "                    \"object_id\": \"john-hancock-selection\",\n" +
  "                    \"sequence_order\": \"02\",\n" +
  "                    \"description_hash\": \"041E\",\n" +
  "                    \"ciphertext\": {\n" +
  "                        \"pad\": \"6134421457232408437\",\n" +
  "                        \"data\": \"12600733893791391007\"\n" +
  "                    },\n" +
  "                    \"crypto_hash\": \"39EA\",\n" +
  "                    \"is_placeholder_selection\": \"00\",\n" +
  "                    \"nonce\": \"019C\",\n" +
  "                    \"proof\": {\n" +
  "                        \"proof_zero_pad\": \"7854032639703357939\",\n" +
  "                        \"proof_zero_data\": \"9337455329456383521\",\n" +
  "                        \"proof_one_pad\": \"9793828469395635107\",\n" +
  "                        \"proof_one_data\": \"3799002493802499905\",\n" +
  "                        \"proof_zero_challenge\": \"D7EF\",\n" +
  "                        \"proof_one_challenge\": \"4A37\",\n" +
  "                        \"challenge\": \"2235\",\n" +
  "                        \"proof_zero_response\": \"2964\",\n" +
  "                        \"proof_one_response\": \"5332\",\n" +
  "                        \"usage\": \"Prove selection's value (0 or 1)\"\n" +
  "                    },\n" +
  "                    \"extended_data\": null\n" +
  "                },\n" +
  "                {\n" +
  "                    \"object_id\": \"write-in-selection\",\n" +
  "                    \"sequence_order\": \"03\",\n" +
  "                    \"description_hash\": \"C6AF\",\n" +
  "                    \"ciphertext\": {\n" +
  "                        \"pad\": \"74463669552307256\",\n" +
  "                        \"data\": \"14614819038667367626\"\n" +
  "                    },\n" +
  "                    \"crypto_hash\": \"DED6\",\n" +
  "                    \"is_placeholder_selection\": \"00\",\n" +
  "                    \"nonce\": \"5434\",\n" +
  "                    \"proof\": {\n" +
  "                        \"proof_zero_pad\": \"10122665376204940651\",\n" +
  "                        \"proof_zero_data\": \"842639258061841682\",\n" +
  "                        \"proof_one_pad\": \"5931810232150118510\",\n" +
  "                        \"proof_one_data\": \"10835937530364904234\",\n" +
  "                        \"proof_zero_challenge\": \"EAE4\",\n" +
  "                        \"proof_one_challenge\": \"E540\",\n" +
  "                        \"challenge\": \"D033\",\n" +
  "                        \"proof_zero_response\": \"1E33\",\n" +
  "                        \"proof_one_response\": \"B0CC\",\n" +
  "                        \"usage\": \"Prove selection's value (0 or 1)\"\n" +
  "                    },\n" +
  "                    \"extended_data\": null\n" +
  "                },\n" +
  "                {\n" +
  "                    \"object_id\": \"justice-supreme-court-4-placeholder\",\n" +
  "                    \"sequence_order\": \"04\",\n" +
  "                    \"description_hash\": \"A191\",\n" +
  "                    \"ciphertext\": {\n" +
  "                        \"pad\": \"1052732449890201973\",\n" +
  "                        \"data\": \"14660837509959826160\"\n" +
  "                    },\n" +
  "                    \"crypto_hash\": \"D3EF\",\n" +
  "                    \"is_placeholder_selection\": \"01\",\n" +
  "                    \"nonce\": \"BAB4\",\n" +
  "                    \"proof\": {\n" +
  "                        \"proof_zero_pad\": \"4556120865590037854\",\n" +
  "                        \"proof_zero_data\": \"189865597233188454\",\n" +
  "                        \"proof_one_pad\": \"11320751153538246476\",\n" +
  "                        \"proof_one_data\": \"11495273652826841791\",\n" +
  "                        \"proof_zero_challenge\": \"8F98\",\n" +
  "                        \"proof_one_challenge\": \"943D\",\n" +
  "                        \"challenge\": \"23E4\",\n" +
  "                        \"proof_zero_response\": \"F09A\",\n" +
  "                        \"proof_one_response\": \"5723\",\n" +
  "                        \"usage\": \"Prove selection's value (0 or 1)\"\n" +
  "                    },\n" +
  "                    \"extended_data\": null\n" +
  "                },\n" +
  "                {\n" +
  "                    \"object_id\": \"justice-supreme-court-5-placeholder\",\n" +
  "                    \"sequence_order\": \"05\",\n" +
  "                    \"description_hash\": \"F10A\",\n" +
  "                    \"ciphertext\": {\n" +
  "                        \"pad\": \"1541960870979102681\",\n" +
  "                        \"data\": \"3444294116341284344\"\n" +
  "                    },\n" +
  "                    \"crypto_hash\": \"E14A\",\n" +
  "                    \"is_placeholder_selection\": \"01\",\n" +
  "                    \"nonce\": \"88B1\",\n" +
  "                    \"proof\": {\n" +
  "                        \"proof_zero_pad\": \"1462678916131973416\",\n" +
  "                        \"proof_zero_data\": \"13341797395390433377\",\n" +
  "                        \"proof_one_pad\": \"2152839272861723245\",\n" +
  "                        \"proof_one_data\": \"539979633487837164\",\n" +
  "                        \"proof_zero_challenge\": \"1978\",\n" +
  "                        \"proof_one_challenge\": \"CC9C\",\n" +
  "                        \"challenge\": \"E614\",\n" +
  "                        \"proof_zero_response\": \"3755\",\n" +
  "                        \"proof_one_response\": \"EF6D\",\n" +
  "                        \"usage\": \"Prove selection's value (0 or 1)\"\n" +
  "                    },\n" +
  "                    \"extended_data\": null\n" +
  "                }\n" +
  "            ],\n" +
  "            \"ciphertext_accumulation\": {\n" +
  "                \"pad\": \"18270637542198392056\",\n" +
  "                \"data\": \"18377930743374613968\"\n" +
  "            },\n" +
  "            \"crypto_hash\": \"2B76\",\n" +
  "            \"nonce\": \"6D12\",\n" +
  "            \"proof\": {\n" +
  "                \"pad\": \"1943371427765234972\",\n" +
  "                \"data\": \"4717085759009076609\",\n" +
  "                \"challenge\": \"7FED\",\n" +
  "                \"response\": \"013A\",\n" +
  "                \"constant\": \"02\",\n" +
  "                \"usage\": \"Prove value within selection's limit\"\n" +
  "            }\n" +
  "        }\n" +
  "    ],\n" +
  "    \"code\": \"084F\",\n" +
  "    \"timestamp\": 1635015400,\n" +
  "    \"crypto_hash\": \"3B2A\",\n" +
  "    \"nonce\": \"9DA6\"\n" +
  "}";

export type EncryptInput = {
  plaintextBallot: PlaintextBallot,
  manifest: Manifest,
  output: ElementModQ
}

const numberList: string[] = ["timestamp", "sequence_order"];
const booleanList: string[] = ["is_placeholder_selection"];
const banList: string[] = ["object_id", "style_id"];

export function from_file_to_class(): CiphertextBallot{
  const result = JSON.parse(json_string, (key, value) => {
    //the purpose of this reviver is to replace string inputs into appropriate primitive objects
    //like number, boolean, and string. More complicated objects are handled at by plainToClass method
    if (banList.includes(key)) {
      return value;
    } else if (numberList.includes(key)) {
      return parseInt(value);
    } else if (booleanList.includes(key)) {
      return value !== "00";
    } else {
      //default case
      return value;
    }
  }
  );
  return plainToClass(CiphertextBallot, result as CiphertextBallot);

}

export function from_file_to_PlaintextBallot(jsonString: string): PlaintextBallot {
  const result = JSON.parse(jsonString, (key, value) => {
    //the purpose of this reviver is to replace string inputs into appropriate primitive objects
    //like number, boolean, and string. More complicated objects are handled at by plainToClass method
    if (banList.includes(key)) {
      return value;
    } else if (numberList.includes(key)) {
      return parseInt(value);
    } else if (booleanList.includes(key)) {
      return value !== "00";
    } else {
      //default case
      return value;
    }
  }
  );
  return plainToClass(PlaintextBallot, result as PlaintextBallot);
}

export function hex_to_bigint(numstr: string): bigint {
  return BigInt("0x" + numstr);
}

export const deserialize_toHex_banlist:string[] = ["timestamp"];

export function serialize_compatible_CiphertextBallot(encrypted_ballot: CiphertextBallot): string{
  return JSON.stringify(encrypted_ballot, (key, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    else if (typeof value === "number" && !deserialize_toHex_banlist.includes(key)) {
      return value.toString(10);
    } else if (typeof value === "boolean") {
      return value == false ? "00" : "01";
    }
    return value;
  }, '\t');
}


// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function object_log(object_to_log: any): string{
  return JSON.stringify(object_to_log, (key, value) => {
    key;
    if (typeof value === "bigint") {
      return value.toString(10);
    }
    // else if (typeof value === "number" && !deserialize_toHex_banlist.includes(key)) {
    //   return value.toString(16);
    // } else if (typeof value === "boolean") {
    //   return value == false ? "00" : "01";
    // }
    return value;
  }, '\t');
}
