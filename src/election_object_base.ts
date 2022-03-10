/**
 * A base object to derive other election objects identifiable by object_id
 */
export interface ElectionObjectBase{
  object_id: string;
}

/**
 * A ordered base object to derive other election objects.
 */
export interface OrderedObjectBase extends ElectionObjectBase{
  /**
   * Used for ordering in a ballot to ensure various encryption primitives are deterministic.
   * The sequence order must be unique and should be representative of how the items are represented
   * on a template ballot in an external system.  The sequence order is not required to be in the order
   * in which they are displayed to a voter.  Any acceptable range of integer values may be provided.
   */
  sequence_order: number;
}

//Sort by sequence order.
export function sequence_order_sort<T extends OrderedObjectBase>(unsorted: T[]): T[] {
  return unsorted.sort((a, b) => a.sequence_order - b.sequence_order);
}
