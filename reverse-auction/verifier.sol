// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0ea41b620f8149ad9296cef4529aa46df748be844f38e2965101852a5b4a0645), uint256(0x24945aeb213f6cbb42b774f0efaecc1c33fb8fcce606d149dca828b12d703123));
        vk.beta = Pairing.G2Point([uint256(0x24c4c944d5dceccb1d786572288ca6d4d62ccf4cf4f07c89f21cb4f0ac528609), uint256(0x004b925bb9108dca36efeac507fe06355433deacd1225b59cc8ff05c3d2f425d)], [uint256(0x170935e59e765288a2b054413371f763cb424b7815aa5f4050376a1a3d8c39d0), uint256(0x1e64865df324331e48dc60da57f2b14fa80812c0bfaf33b1a08d6eb05d49516e)]);
        vk.gamma = Pairing.G2Point([uint256(0x0767fdf317c758793206c83bb5e96badff853620cb637eba28a1b35cbb733c1e), uint256(0x248b3f1360d4db81ec2abd7a9e03f230eaab4fb14540065683ba59676ffb72d4)], [uint256(0x19b957b21e42fead1301109c43725c1c1a9674fbfe6a7345f309f31a77f9c52a), uint256(0x304c857811a05cf0f8e0f5959ce69f13cc2c6a8e4407acf1fcf0373b9da2a217)]);
        vk.delta = Pairing.G2Point([uint256(0x00eec18cfb25c2863c7aacc54c9fe1ac3bf535b42d1f9d7df0b72842bffa230c), uint256(0x1359182a8a41a47403e2f9b6d11e9369d2d209f21f0432fce281e41149782633)], [uint256(0x149db17e6535d365b7b8c41d425522614c9a0e7819ffb83a463b9dca290a301f), uint256(0x192b332d22aa80532945d71854febf306bbe6c037cc11e38a5cbf6972989d173)]);
        vk.gamma_abc = new Pairing.G1Point[](17);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x03f156bea9342d5ec2ad568ea9e8e0d8294a2c08dad13f4169193f9f93038a93), uint256(0x13579d2991eb5722b188b90fdfa5b0ae42a91280137b1e0c87ded8c69870dfca));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x07ba4db61da9069d73881e83c9e7354cd4fc078fdec9a95823133a7dc436d64b), uint256(0x21de2ee8953bd98a619530bdce8994a58f70a6f73f08db46e1dfb140af93856a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x18cfc3f24acc9ec100dd1e0a5345b94c77fa63c30a0a4aac7dd88ce423bf11d0), uint256(0x0e79956d19b0fc2eecdb30d29b021eec191b88a140cd209e8ec6a766e8e1b8c5));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x27fb465209016f14fcf8619c3251095cbbf1c7345ef6cf4bdaf5148202f25922), uint256(0x11f60caf2f274872941df15667852c2c55899167696d63fe870a03531e5a899e));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x09eb30f589310cf1be413d383268591ab19e1d3601d1b938e86b39cffc31349c), uint256(0x2ab7c2c98f5a67944155b0f9d3a87834fb4da5dcfa7273b074787f67da245c8b));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x056aeb4f364f713c83d7cedbabb1866e36c021653433d6ed99ba76bf575e5fb7), uint256(0x0e12b4c54cf4fe59c2c3d37f83f8d101fdb1cdd41989e40dac99dcb2ee306bed));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x15b2397e9365480373cc4d7e41d2729d59b94337e9ad98ef3c14499599fe9e2b), uint256(0x1e947c7dbafc629afc22fe619840ce39d0a458d9a66f4542225392fb4b40e33c));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0b50a30608849437f3e94bae1c075f2c7aadef7b78a6807393dea84f3a0ddbdd), uint256(0x12da1b9b5dd7ac0ce493ea61bb68eb875a04ec85532b1b4d1616e81d011ad135));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2b7044a330514ce9f53cd3305915ddc3383a4228fbc4ef62ac88c0af346a799b), uint256(0x15b2474e3521780e1545af2066cad72248643de431e19565d1e953630f00240e));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0fd04bfbb175d170635a899efca392a5a8a8d76c4c1e0446d4d7d49caf291ffe), uint256(0x2d4d04d3e2fd0f7f31169f677fdb579ff211f5de1b39e8205027073a7db28062));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1060386f88d9e79b511a22018237553c52498e33f920a302ecff2c015b950f29), uint256(0x265adadc961a8cf02a9c11719a7de66c26d5dfaa17efeff1430caa0cb716a1d0));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x23b9287d581d90d679e9bf889769e402c76fd90dbcf158865903feb01b18d803), uint256(0x1ccbf6f1e6ec59657b8f2f41bddcd5578378866b6300045fe946d275863d115b));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x192279a0018e5c2a99a6c63a667e110ccbcdb4db6760f45b8d2001b3439e1c4e), uint256(0x18b84d6b2d9053436a0f60e9dae536f53f29263a4a1c1201a4e0fd9da0c49161));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x26df37c5bfdd265dd9de268ed1a6c25ed7beaba6247d5167b49813a0b7fd04c8), uint256(0x2e4eb78fb7bfeb2e2434000353bb4e27893d415ba87f17030aa9101f643182cf));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x211efcb90e45d38a848b5a4104777e1c94514ec340b6ff0c0da26bfe64db96dc), uint256(0x2421a50dae65b34dc0fbe91af4ebffcb199a670792c113b702f89093b44ed79e));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x047cbc8b1afc1a1fa1b3b703f2b661e716b9387b0786cc8b6a2769fc3e888918), uint256(0x15889969b3fc53821f045629475e4f57b0895f76881ad13703d12ef9e3b1b730));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1b91b754b6cc302126754b3642d2e1773def0f365cddb3205d2992597b6817b9), uint256(0x1b3c273c9a1bc4e4fe578c1efddb2ac143748266d67df128dcc8db694817b0f3));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[16] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](16);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
