import {CryptoHashable, hash_elems} from "./hash";
import {ElectionObjectBase, OrderedObjectBase} from "./election_object_base";
import {ElementModQ} from "./group";
import {_list_eq} from "./simple_election_data";
import {get_optional} from "./utils";
import {Transform, Type} from "class-transformer";
import moment from 'moment';

/**
 * enumerations for the `ElectionReport` entity
 * see: https://developers.google.com/elections-data/reference/election-type
 */

export enum ElectionType{
  unknown = "unknown",
  general = "general",
  partisan_primary_closed = "partisan_primary_closed",
  partisan_primary_open = "partisan_primary_open",
  primary = "primary",
  runoff = "runoff",
  special = "special",
  other = "other"
}

/**
 * Enumeration for the type of geopolitical unit
 * see: https://developers.google.com/elections-data/reference/reporting-unit-type
 */
export enum ReportingUnitType{
  unknown = "unknown",
  ballot_batch = "ballot_batch",
  ballot_style_area = "ballot_style_area",
  borough = "borough",
  city = "city",
  city_council = "city_council",
  combined_precinct = "combined_precinct",
  congressional = "congressional",
  country = "country",
  county = "county",
  county_council = "county_council",
  drop_box = "drop_box",
  judicial = "judicial",
  municipality = "municipality",
  polling_place = "polling_place",
  precinct = "precinct",
  school = "school",
  special = "special",
  split_precinct = "split_precinct",
  state = "state",
  state_house = "state_house",
  state_senate = "state_senate",
  township = "township",
  utility = "utility",
  village = "village",
  vote_center = "vote_center",
  ward = "ward",
  water = "water",
  other = "other",
}

/**
 * Enumeration for contest algorithm or rules in the `Contest` entity
 * see: https://developers.google.com/elections-data/reference/vote-variation
 */
export enum VoteVariationType {
  unknown = "unknown",
  one_of_m = "one_of_m",
  approval = "approval",
  borda = "borda",
  cumulative = "cumulative",
  majority = "majority",
  n_of_m = "n_of_m",
  plurality = "plurality",
  proportional = "proportional",
  range = "range",
  rcv = "rcv",
  super_majority = "super_majority",
  other = "other",
}

/**
 * Use this as a type for character strings
 * See: https://developers.google.com/elections-data/reference/annotated-string
 */
export class AnnotatedString extends CryptoHashable {
  annotation = "";
  value = "";

  constructor(annotation:string, value:string) {
    super();
    this.annotation = annotation;
    this.value = value;
  }

  //Hash representation of the object.
  crypto_hash(): ElementModQ {
    return hash_elems([this.annotation, this.value]);
  }

}

/**
 * The ISO-639 language
 * see: https://en.wikipedia.org/wiki/ISO_639
 */
export class Language extends CryptoHashable {
  value: string;
  language = "en";

  constructor(value:string, language: string) {
    super();
    this.value = value;
    this.language = language;
  }

  //A hash representation of the object
  crypto_hash(): ElementModQ {
    return hash_elems([this.value, this.language]);
  }

}

/**
 * Data entity used to represent multi-national text. Use when text on a ballot contains multi-national text.
 * See: https://developers.google.com/elections-data/reference/internationalized-text
 */
export class InternationalizedText extends CryptoHashable {
  @Type(()=>Language)
  text: Language[] = [];

  constructor(text?: Language[]) {
    super();
    this.text = text ? text : [];
  }

  //A hash representation of the object.
  crypto_hash(): ElementModQ {
    return hash_elems([this.text]);
  }

}

/**
 * For defining contact information about objects such as persons, boards of authorities, and organizations.
 * See: https://developers.google.com/elections-data/reference/contact-information
 */
export class ContactInformation extends CryptoHashable{
  address_line?: string[] = undefined;

  @Type(()=>AnnotatedString)
  email?: AnnotatedString[] = undefined;

  @Type(()=>AnnotatedString)
  phone?: AnnotatedString[] = undefined;

  name?: string = undefined;

  constructor(address_line?: string[], email?: AnnotatedString[], phone?:AnnotatedString[], name?: string) {
    super();
    this.address_line = address_line;
    this.email = email;
    this.phone = phone;
    this.name = name;
  }

  crypto_hash(): ElementModQ {
    return hash_elems([this.name, this.address_line, this.email, this.phone]);
  }

}

/**
 * Use this entity for defining geopolitical units such as cities, districts, jurisdictions, or precincts,
 * for the purpose of associating contests, offices, vote counts, or other information with the geographies.
 * See: https://developers.google.com/elections-data/reference/gp-unit
 */
export class GeopoliticalUnit extends CryptoHashable implements ElectionObjectBase {
  object_id:string;
  name: string;
  @Transform(({value}) => value as ReportingUnitType)
  type: ReportingUnitType;
  @Type(() => ContactInformation)
  contact_information?: ContactInformation = undefined;

  constructor(object_id:string,
              name: string,
              type: ReportingUnitType,
              contact_information?: ContactInformation) {
    super();
    this.object_id = object_id;
    this.name = name;
    this.type = type;
    this.contact_information = contact_information;
  }
  crypto_hash(): ElementModQ {
    return hash_elems([this.object_id, this.name, this.type.toString(), this.contact_information]);
  }
}

/**
 * A BallotStyle works as a key to uniquely specify a set of contests. See also `ContestDescription`.
 */
export class BallotStyle extends CryptoHashable implements ElectionObjectBase {
  object_id: string;

  geopolitical_unit_ids?: string[] = undefined;
  party_ids?: string[] = undefined;
  image_uri?: string = undefined;

  constructor(object_id: string, geopolitical_unit_ids?: string[], party_ids?: string[], image_uri?: string) {
    super();
    this.object_id = object_id;
    this.geopolitical_unit_ids = geopolitical_unit_ids;
    this.party_ids = party_ids;
    this.image_uri = image_uri;
  }

  //A hash representation of the object
  crypto_hash(): ElementModQ {
    return hash_elems([this.object_id, this.geopolitical_unit_ids, this.party_ids, this.image_uri]);
  }

}

/**
 * Use this entity to describe a political party that can then be referenced from other entities.
 * See: https://developers.google.com/elections-data/reference/party
 */
export class Party extends CryptoHashable implements ElectionObjectBase {
  object_id: string;
  @Type(() => InternationalizedText)
  name: InternationalizedText = new InternationalizedText();
  abbreviation?: string = undefined;
  color?: string = undefined;
  logo_uri?: string = undefined;

  constructor(object_id:string,
              name: InternationalizedText,
              abbreviation?: string,
              color?: string,
              logo_uri?: string) {
    super();
    this.object_id = object_id;
    this.name = name;
    this.abbreviation = abbreviation;
    this.color = color;
    this.logo_uri = logo_uri;
  }

  //Returns the object identifier associated with the Party.
  get_party_id(): string{
    return this.object_id;
  }

  crypto_hash(): ElementModQ {
    return hash_elems([this.object_id, this.name, this.abbreviation, this.color, this.logo_uri]);
  }
}

/**
 * Entity describing information about a candidate in a contest.
 * See: https://developers.google.com/elections-data/reference/candidate
 * Note: The ElectionGuard Data Spec deviates from the NIST model in that
 * selections for any contest type are considered a "candidate".
 * for instance, on a yes-no referendum contest, two `candidate` objects
 * would be included in the model to represent the `affirmative` and `negative`
 * selections for the contest.  See the wiki, readme's, and tests in this repo for more info
 */
export class Candidate extends CryptoHashable implements ElectionObjectBase {
  object_id:string;
  @Type(() => InternationalizedText)
  name: InternationalizedText = new InternationalizedText();
  party_id?: string = undefined;
  image_uri?: string = undefined;
  is_write_in?: boolean = undefined;

  constructor(object_id:string,
              name: InternationalizedText,
              party_id?: string,
              image_uri?: string,
              is_write_in?: boolean) {
    super();
    this.object_id = object_id;
    this.name = name;
    this.party_id = party_id;
    this.image_uri = image_uri;
    this.is_write_in = is_write_in;
  }

  get_candidate_id():string {
    return this.object_id;
  }

  crypto_hash(): ElementModQ {
    return hash_elems([this.object_id, this.name, this.party_id, this.image_uri]);
  }
}

/**
 *Data entity for the ballot selections in a contest,
 * for example linking candidates and parties to their vote counts.
 * See: https://developers.google.com/elections-data/reference/ballot-selection
 * Note: The ElectionGuard Data Spec deviates from the NIST model in that
 * there is no difference for different types of selections.
 * The ElectionGuard Data Spec deviates from the NIST model in that
 * `sequence_order` is a required field since it is used for ordering selections
 * in a contest to ensure various encryption primitives are deterministic.
 * For a given election, the sequence of selections displayed to a user may be different
 * however that informat
 */
export class SelectionDescription extends CryptoHashable implements OrderedObjectBase {
  object_id: string;
  sequence_order: number;

  candidate_id: string;

  constructor(object_id:string, sequence_order: number, candidate_id: string) {
    super();
    this.object_id = object_id;
    this.sequence_order = sequence_order;
    this.candidate_id = candidate_id;
  }

  //A hash representation of the object
  crypto_hash(): ElementModQ {
   return hash_elems([this.object_id, this.sequence_order, this.candidate_id]);
  }

}

/**
 * Use this data entity for describing a contest and linking the contest
 * to the associated candidates and parties.
 * See: https://developers.google.com/elections-data/reference/contest
 * Note: The ElectionGuard Data Spec deviates from the NIST model in that
 * `sequence_order` is a required field since it is used for ordering selections
 * in a contest to ensure various encryption primitives are deterministic.
 * For a given election, the sequence of contests displayed to a user may be different
 * however that information is not captured by default when encrypting a specific ballot.
 */
export class ContestDescription extends CryptoHashable implements OrderedObjectBase {
  object_id: string;
  sequence_order: number;

  electoral_district_id: string;

  @Transform(({value}) => value as VoteVariationType)
  vote_variation: VoteVariationType;

  // Number of candidates that are elected in the contest ("n" of n-of-m).
  // Note: a referendum is considered a specific case of 1-of-m in ElectionGuard
  number_elected: number;

  // Maximum number of votes/write-ins per voter in this contest. Used in cumulative voting
  // to indicate how many total votes a voter can spread around. In n-of-m elections, this will
  // be None.
  votes_allowed?: number;

  // Name of the contest, not necessarily as it appears on the ballot.
  name: string;

  // For associating a ballot selection for the contest, i.e., a candidate, a ballot measure.
  @Type(() => SelectionDescription)
  ballot_selections:SelectionDescription[] = [];

  // Title of the contest as it appears on the ballot.
  @Type(() => InternationalizedText)
  ballot_title?: InternationalizedText = undefined;

  // Subtitle of the contest as it appears on the ballot.
  @Type(() => InternationalizedText)
  ballot_subtitle?: InternationalizedText = undefined;

  constructor(object_id: string,
              sequence_order: number,
              electoral_district_id: string,
              vote_variation: VoteVariationType,
              number_elected: number,
              name:string,
              ballot_selections:SelectionDescription[],
              votes_allowed?:number,
              ballot_title?: InternationalizedText,
              ballot_subtitle?: InternationalizedText) {
    super();
    this.object_id = object_id;
    this.sequence_order = sequence_order;
    this.electoral_district_id = electoral_district_id;
    this.vote_variation = vote_variation;
    this.number_elected = number_elected;
    this.votes_allowed = votes_allowed;
    this.name = name;
    this.ballot_selections = ballot_selections;
    this.ballot_title = ballot_title;
    this.ballot_subtitle = ballot_subtitle;
  }

  //!!! This operation changes the order of this and other's ballot_selections object order
  //Let Arthur Know if this is a problem
  equals(other: ContestDescription): boolean {
    return (
      this.electoral_district_id == other.electoral_district_id
      && this.sequence_order == other.sequence_order
      && this.vote_variation == other.vote_variation
      && this.number_elected == other.number_elected
      && this.votes_allowed == other.votes_allowed
      && this.name == other.name
      && _list_eq(this.ballot_selections, other.ballot_selections)
      && this.ballot_title == other.ballot_title
      && this.ballot_subtitle == other.ballot_subtitle
    );
  }

  /**
   * Given a ContestDescription, deterministically derives a "hash" of that contest,
   * suitable for use in ElectionGuard's "base hash" values, and for validating that
   * either a plaintext or encrypted voted context and its corresponding contest
   * description match up.
   */
  crypto_hash(): ElementModQ {

    return hash_elems([
      this.object_id,
      this.sequence_order,
      this.electoral_district_id,
      VoteVariationType[this.vote_variation],
      this.ballot_title,
      this.ballot_subtitle,
      this.name,
      this.number_elected,
      this.votes_allowed,
      this.ballot_selections,
    ]);
  }

  //Check the validity of the contest object by verifying its data
  is_valid(): boolean {
    const contest_has_valid_number_elected = this.number_elected <=
      this.ballot_selections.length;
    const contest_has_valid_votes_allowed = (
      this.votes_allowed == null || this.number_elected <= this.votes_allowed
    );

    // verify the candidate_ids, selection object_ids, and sequence_ids are unique
    const candidate_ids = new Set<string>();
    const selection_ids = new Set<string>();
    const sequence_ids = new Set<number>();
    // let selection_count = 0;
    const expected_selection_count = this.ballot_selections.length;

    for (const selection of this.ballot_selections) {
      // selection_count += 1;
      // validate the object_id
      if (!selection_ids.has(selection.object_id)) {
        selection_ids.add(selection.object_id);
      }
      // validate the sequence_order
      if (!sequence_ids.has(selection.sequence_order)) {
        sequence_ids.add(selection.sequence_order);
      }
      // validate the candidate id
      if (!candidate_ids.has(selection.candidate_id)){
        candidate_ids.add(selection.candidate_id);
      }
    }

    const selections_have_valid_candidate_ids = (
      candidate_ids.size == expected_selection_count
    );
    const selections_have_valid_selection_ids = (
      selection_ids.size == expected_selection_count
    );
    const selections_have_valid_sequence_ids = (
      sequence_ids.size == expected_selection_count
    );

    const success = (
      contest_has_valid_number_elected
    && contest_has_valid_votes_allowed
    && selections_have_valid_candidate_ids
    && selections_have_valid_selection_ids
    && selections_have_valid_sequence_ids
  );

    //Python library do logging here
    // if (!success):
      // log_warning(
      //   "Contest %s failed validation check: %s",
      //   self.object_id,
      //   str(
      //     {
      //       "contest_has_valid_number_elected": contest_has_valid_number_elected,
      //       "contest_has_valid_votes_allowed": contest_has_valid_votes_allowed,
      //       "selections_have_valid_candidate_ids": selections_have_valid_candidate_ids,
      //       "selections_have_valid_selection_ids": selections_have_valid_selection_ids,
      //       "selections_have_valid_sequence_ids": selections_have_valid_sequence_ids,
      //     }
      //   ),
      // )

    return success

  }

}

/**
 * Use this entity to describe a contest that involves selecting one or more candidates.
 * See: https://developers.google.com/elections-data/reference/contest
 * Note: The ElectionGuard Data Spec deviates from the NIST model in that
 * this subclass is used purely for convenience
 */
class CandidateContestDescription extends ContestDescription{
  primary_party_ids: string[] = [];

  constructor(object_id: string,
              sequence_order: number,
              electoral_district_id: string,
              vote_variation: VoteVariationType,
              number_elected: number,
              votes_allowed:number,
              name:string,
              ballot_selections:SelectionDescription[],
              ballot_title: InternationalizedText,
              ballot_subtitle: InternationalizedText,
              primary_party_ids: string[]) {
    super(object_id,
      sequence_order,
      electoral_district_id,
      vote_variation,
      number_elected,
      name,
      ballot_selections,
      votes_allowed,
      ballot_title,
      ballot_subtitle);
    this.primary_party_ids = primary_party_ids;
  }


}

CandidateContestDescription;

/**
 * Use this entity to describe a contest that involves selecting exactly one 'candidate'.
 * See: https://developers.google.com/elections-data/reference/contest
 * Note: The ElectionGuard Data Spec deviates from the NIST model in that
 * this subclass is used purely for convenience
 */
class ReferendumContestDescription extends ContestDescription{
  //python Electionguard is empty here as well. this is expected.
}

ReferendumContestDescription;

/**
 * ContestDescriptionWithPlaceholders is a `ContestDescription` with ElectionGuard `placeholder_selections`.
 * (The ElectionGuard spec requires for n-of-m elections that there be *exactly* n counters that are one
 * with the rest zero, so if a voter deliberately undervotes, one or more of the placeholder counters will
 * become one. This allows the `ConstantChaumPedersenProof` to verify correctly for undervoted contests.)
 */
export class ContestDescriptionWithPlaceholders extends ContestDescription {
  @Type(()=> SelectionDescription)
  placeholder_selections: SelectionDescription[] = [];

  constructor(object_id: string,
              sequence_order: number,
              electoral_district_id: string,
              vote_variation: VoteVariationType,
              number_elected: number,
              name:string,
              ballot_selections:SelectionDescription[],
              placeholder_selections: SelectionDescription[],
              votes_allowed?:number,
              ballot_title?: InternationalizedText,
              ballot_subtitle?: InternationalizedText,
              ) {
    super(object_id,
      sequence_order,
      electoral_district_id,
      vote_variation,
      number_elected,
      name,
      ballot_selections,
      votes_allowed,
      ballot_title,
      ballot_subtitle,
      );
    this.placeholder_selections = placeholder_selections;
  }

  //Checks is contest description is valid
  is_valid(): boolean {
    const contest_description_validates = super.is_valid();
    return (
      contest_description_validates
      && this.placeholder_selections.length == this.number_elected
    );
  }

  //Checks is contest description is placeholder
  is_placeholder(selection: SelectionDescription): boolean {
    return this.placeholder_selections.includes(selection);
  }

  //Gets the description for a particular id
  selection_for(selection_id: string): SelectionDescription | null {
    const matching_selections: SelectionDescription[]
      = this.ballot_selections.filter(selection => selection.object_id == selection_id);
    if (matching_selections.length > 0) {
      return matching_selections[0];
    }

    const matching_placeholders: SelectionDescription[]
      = this.placeholder_selections.filter(selection => selection.object_id == selection_id);

    if (matching_placeholders.length > 0) {
      return matching_placeholders[0];
    }

    return null;
  }

}

/**
 * Use this entity for defining the structure of the election and associated
 * information such as candidates, contests, and vote counts.  This class is
 * based on the NIST Election Common Standard Data Specification.  Some deviations
 * from the standard exist.
 * This structure is considered an immutable input object and should not be changed
 * through the course of an election, as it's hash representation is the basis for all
 * other hash representations within an ElectionGuard election context.
 * See: https://developers.google.com/elections-data/reference/election
 */
export class Manifest extends CryptoHashable {
  election_scope_id: string;
  spec_version: string;
  @Transform(({value}) => value as ElectionType)
  type: ElectionType;
  //TODO: double check the datetime object usage in python to makesure this is equivalent
  @Type(() => Date)
  start_date: Date;
  @Type(() => Date)
  end_date: Date;
  @Type(() => GeopoliticalUnit)
  geopolitical_units: GeopoliticalUnit[];
  @Type(() => Party)
  parties: Party[];
  @Type(() => Candidate)
  candidates: Candidate[];
  @Type(() => ContestDescription)
  contests: ContestDescription[];
  @Type(() => BallotStyle)
  ballot_styles: BallotStyle[];
  @Type(() => InternationalizedText)
  name?: InternationalizedText = undefined;
  @Type(() => ContactInformation)
  contact_information?: ContactInformation = undefined;

  constructor(
    election_scope_id: string,
    spec_version: string,
    type: ElectionType,
    start_date: Date,
    end_date: Date,
    geopolitical_units: GeopoliticalUnit[],
    parties: Party[],
    candidates: Candidate[],
    contests: ContestDescription[],
    ballot_styles: BallotStyle[],
    name?: InternationalizedText,
    contact_information?: ContactInformation
  ) {
    super();
    this.election_scope_id = election_scope_id;
    this.spec_version = spec_version;
    this.type = type;
    this.start_date = start_date;
    this.end_date = end_date;
    this.geopolitical_units = geopolitical_units;
    this.parties = parties;
    this.candidates = candidates;
    this.contests = contests;
    this.ballot_styles = ballot_styles;
    this.name = name;
    this.contact_information = contact_information;
  }

  crypto_hash(): ElementModQ {
    //TODO: date object to ISO date string
    // let st = new Date("2000-01-01T00:00:00");
    let start_date = moment(this.start_date).format();
    start_date = start_date.slice(0, start_date.length - 6) + "Z";
    let end_date = moment(this.end_date).format();
    end_date = end_date.slice(0, end_date.length - 6) + "Z";

    return hash_elems([
      this.election_scope_id,
      this.type.toString(),
      // "2000-01-01T00:00:00Z",
      // "2000-01-01T00:00:00Z",
      start_date,
      end_date,
      this.name,
      this.contact_information,
      this.geopolitical_units,
      this.parties,
      this.contests,
      this.ballot_styles]);
  }

  //TODO Is valid method not implemented, let's see if it is needed later

}

/**
 * `InternalManifest` is a subset of the `Manifest` structure that specifies
 * the components that ElectionGuard uses for conducting an election.  The key component is the
 * `contests` collection, which applies placeholder selections to the `Manifest` contests
 */
export class InternalManifest{
  @Type(() => Manifest)
  manifest: Manifest;
  @Type(() => GeopoliticalUnit)
  geopolitical_units: GeopoliticalUnit[];
  @Type(() => ContestDescriptionWithPlaceholders)
  contests: ContestDescriptionWithPlaceholders[];
  @Type(() => BallotStyle)
  ballot_styles: BallotStyle[];
  @Transform(({value}) => new ElementModQ(BigInt("0x" + value)))
  manifest_hash: ElementModQ;
  constructor(
    manifest: Manifest) {
    this.manifest = manifest;
    this.manifest_hash = this.manifest.crypto_hash();
    this.geopolitical_units = this.manifest.geopolitical_units;
    this.ballot_styles = this.manifest.ballot_styles;
    this.contests = InternalManifest._generate_contests_with_placeholders(this.manifest);
  }

  /**
   * Get contest by id
   * @param contest_id contest id
   */
  contest_for(contest_id: string): ContestDescriptionWithPlaceholders | null {
    const matching_contests:ContestDescriptionWithPlaceholders[]
      = this.contests.filter(contest => contest.object_id == contest_id);

    if (matching_contests.length > 0) {
      return matching_contests[0];
    }
    return null;
  }

  /**
   * Get a ballot style for a specified ballot_style_id
   * @param ballot_style_id the ballot style id
   */
  get_ballot_style(ballot_style_id: string): BallotStyle | null {
    const style: BallotStyle[]
      = this.ballot_styles.filter(ballot_style => ballot_style.object_id == ballot_style_id);

    if (style.length > 0) {
      return style[0];
    }

    return null;
  }

  /**
   * Get contests for a ballot style
   * @param ballot_style_id ballot style id
   */
  get_contests_for(ballot_style_id: string): ContestDescriptionWithPlaceholders[] {
    const style = get_optional(this.get_ballot_style(ballot_style_id));
    if (style.geopolitical_unit_ids == null) {
      return [];
    }
    const gp_unit_ids = style.geopolitical_unit_ids;
    return this.contests.filter(contest => gp_unit_ids.includes(contest.electoral_district_id));
  }

  /**
   * For each contest, append the `number_elected` number
   * of placeholder selections to the end of the contest collection
   * @param manifest the manifest of this election
   */
   static _generate_contests_with_placeholders(
    manifest: Manifest
  ): ContestDescriptionWithPlaceholders[]{
    const contests: ContestDescriptionWithPlaceholders[] = [];
    for (const contest of manifest.contests) {
      const placeholder_selections = generate_placeholder_selections_from(contest, contest.number_elected);
      contests.push(contest_description_with_placeholders_from(contest, placeholder_selections));
    }
    return contests;
  }

}

/**
 * Generates a placeholder selection description
 * @param description contest description
 * @param placeholders list of placeholder descriptions of selections
 */
function contest_description_with_placeholders_from(
  description: ContestDescription,
  placeholders: SelectionDescription[]): ContestDescriptionWithPlaceholders{
  return new ContestDescriptionWithPlaceholders(
    description.object_id,
    description.sequence_order,
    description.electoral_district_id,
    description.vote_variation,
    description.number_elected,
    description.name,
    description.ballot_selections,
    placeholders,
    description.votes_allowed,
    description.ballot_title,
    description.ballot_subtitle,
  );

}

/**
 * Generates a placeholder selection description that is unique so it can be hashed
 * @param contest the contest description
 * @param use_sequence_id an optional integer unique to the contest identifying this selection's place in the contest
 */
function generate_placeholder_selection_from(
  contest: ContestDescription,
  use_sequence_id?: number
): SelectionDescription | null{
  const sequence_ids = contest.ballot_selections.map(selection => selection.sequence_order);
  if (use_sequence_id == null) {
    //if no sequence order is specified, take the max
    use_sequence_id = Math.max(...sequence_ids) + 1;
  } else if (sequence_ids.includes(use_sequence_id)) {
    //mismatched placeholder selection {use_sequence_id} already exists
    return null;
  }
  const placeholder_object_id = contest.object_id + "-" + use_sequence_id;
  return new SelectionDescription(
    placeholder_object_id + "-placeholder",
    use_sequence_id,
    placeholder_object_id + "-candidate");
}

/**
 * Generates the specified number of placeholder selections in
 * ascending sequence order from the max selection sequence orderf
 * @param contest ContestDescription for input
 * @param count optionally specify a number of placeholders to generate
 * @return: a collection of `SelectionDescription` objects, which may be empty
 */
function generate_placeholder_selections_from(
  contest: ContestDescription, count: number
): SelectionDescription[]{
  const max_sequence_order = Math.max(
    ...(contest.ballot_selections.map(selection => selection.sequence_order))
  );
  const selections: SelectionDescription[] = [];
  for (let i = 0; i < count; i++) {
    const sequence_order = max_sequence_order + 1 + i;
    selections.push(get_optional(generate_placeholder_selection_from(contest, sequence_order)));
  }
  return selections;
}
