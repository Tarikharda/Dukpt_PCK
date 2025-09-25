package org.example.utils.security.dukpt;

public class BitSet extends java.util.BitSet {
    public static final int DEFAULT_SIZE = 8;
    private static final long serialVersionUID = 1L;
    private int size;

    /**
     * Creates a BitSet with DEFAULT_SIZE bits.
     */
    public BitSet() {
        super(DEFAULT_SIZE);
        size = DEFAULT_SIZE;
    }

    /**
     * Creates a BitSet with a specified number of bits.
     * @param nbits The size of the created BitSet.
     */
    public BitSet(int nbits) {
        super(nbits);
        size = nbits;
    }

    @Override
    public BitSet get(int low, int high) {
        BitSet n = new BitSet(high-low);
        for (int i=0; i < (high-low); i++) {
            n.set(i, this.get(low+i));
        }
        return n;
    }

    /**
     * Returns the size of the BitSet as declared or requested (the fixed-length).
     */
    public int bitSize() {
        return size;
    }
}
