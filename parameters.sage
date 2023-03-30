# zekrom-arkworks
# Copyright (C) 2023
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from sage.all_cmdline import *   
from fileinput import filename
from Crypto.Hash import SHAKE128, SHAKE256
from tqdm import tqdm


def get_random_element(p, shake, rejection=False):
    Fp = FiniteField(p)
    bstring = shake.read(ceil(len(bin(p)[2:])/8) + 1)
    val = sum(256 ** j * ZZ(bstring[j]) for j in range(len(bstring)))
    while rejection and val >= p:
        bstring = shake.read(ceil(len(bin(p)[2:])/8) + 1)
        val = sum(256 ** j * ZZ(bstring[j]) for j in range(len(bstring)))
    return Fp(val % p)


def get_n_random_elements(p, n, shake, rejection=False):
    vals = []
    for i in range(n):
        vals.append(get_random_element(p, shake, rejection))
    return vals


def check_ab(alpha, beta, p):
    tmp = (alpha * alpha - 4 * beta) % p
    return kronecker(tmp, p) == -1


def get_alpha_beta(p, shake):
    while 1:
        alpha, beta = get_random_element(p, shake), get_random_element(p, shake)
        tmp = (alpha * alpha - 4 * beta) % p
        if kronecker(tmp, p) == -1:
            return alpha, beta


def get_inverse(x, p):
    return (xgcd(x, p-1)[1]) % p


def get_mds_matrix(p, m):
    # get a primitive element
    Fp = FiniteField(p)
    g = Fp(2)
    while g.multiplicative_order() != p - 1:
        g = g + 1
    # get a systematic generator matrix for the code
    V = matrix([[g ** (i * j) for j in range(0, 2 * m)] for i in range(0, m)])
    V_ech = V.echelon_form()

    # the MDS matrix is the transpose of the right half of this matrix
    MDS = V_ech[:, m:].transpose()
    return MDS


def get_round_constants_rescue(p, m, capacity, security_level, n):
    shake = SHAKE256.new()
    shake.update(bytes("Rescue-XLIX (%i,%i,%i,%i)" % (p, m, capacity, security_level), "ascii"))
    return get_n_random_elements(p, m*n, shake)


def get_round_constants_ciminion(p, n):
    shake = SHAKE256.new()
    shake.update(bytes(f"GF({p})", "ascii"))
    return get_n_random_elements(p, 4*n, shake, True)


def get_number_of_rounds_rescue(p, m, c, s, d):
    r = m - c
    def dcon(N): return floor(0.5 * (d-1) * m * (N-1) + 2)
    def v(N): return m*(N-1)+r
    target = 2 ** s
    for l1 in range(1, 25):
        if binomial(v(l1) + dcon(l1), v(l1)) ** 2 > target:
            break
    return ceil(1.5*max(5, l1))


def get_round_constants_neptune(p, seed, m, n):
    shake = SHAKE128.new()
    shake.update(bytes("Neptune", "ascii"))
    for v in seed:
        shake.update(bytes(v))
    consts = get_n_random_elements(p, n*m, shake)
    gamma = get_random_element(p, shake)
    int_matrix = get_n_random_elements(p, m, shake)
    return consts, gamma, int_matrix


def get_params_griffin(p, seed, m, n):
    shake = SHAKE128.new()
    shake.update(bytes("Griffin", "ascii"))
    for v in seed:
        shake.update(bytes(v));
    consts = get_n_random_elements(p, n*m, shake)
    alpha, beta = get_alpha_beta(p, shake)
    return alpha, beta, consts

def get_rounds_concrete(p, seed, m, n):
    shake = SHAKE128.new()
    shake.update(bytes("ReinforcedConcrete", "ascii"))
    for v in seed:
        shake.update(bytes(v));
    consts = get_n_random_elements(p, n*m, shake)
    return consts


def get_nb_rounds_neptune(d, p, t, s):
    re = 6    
    ri_p_1 = ceil((min(s, math.log(p,2)) - 6)/math.log(d, 2) + 3 + t + log(t, d))
    ri_p_2 = ceil((s/2) - 4*t - 2)
    
    return re, ceil(1.125 * max(ri_p_1, ri_p_2))

def get_mds_matrix(p, m):
    # get a primitive element
    Fp = FiniteField(p)
    g = Fp(2)
    while g.multiplicative_order() != p - 1:
        g = g + 1
    # get a systematic generator matrix for the code
    V = matrix([[g ** (i * j) for j in range(0, 2 * m)] for i in range(0, m)])
    V_ech = V.echelon_form()
    # the MDS matrix is the transpose of the right half of this matrix
    MDS = V_ech[:, m:].transpose()
    return MDS


### ----- Constants ----- ###
bls12 = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
vesta = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

m = 3
m_neptune = 4
r = 1
c = 2
c_neptune = 3
d = 5
s = 128

seeding_vesta = [[1, 0, 0, 0, 33, 235, 70, 140], [221, 168, 148, 9, 252, 152, 70, 34], [0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 64]]
seeding_bls12 = [[1, 0, 0, 0, 255, 255, 255, 255], [254, 91, 254, 255, 2, 164, 189, 83], [5, 216, 161, 9, 8, 216, 57, 51], [72, 125, 157, 41, 83, 167, 237, 115]]

d_inv_bls12 = get_inverse(d, bls12)
d_inv_vesta = get_inverse(d, vesta)

with tqdm(total=int(5), desc="Progress", unit="constructions", ascii=True) as pbar:
    ### ----- Rescue Prime ----- ###
    filename = 'rescue.txt'

    n_vesta = get_number_of_rounds_rescue(vesta, m, c, s, d)
    n_bls12 = get_number_of_rounds_rescue(bls12, m, c, s, d)

    mds_vesta = get_mds_matrix(vesta, m)
    mds_bls12 = get_mds_matrix(bls12, m)

    rounds_vesta = get_round_constants_rescue(vesta, m, c, s, n_vesta)
    rounds_bls12 = get_round_constants_rescue(bls12, m, c, s, n_bls12)

    with open(f'config/{filename}', "w") as f:
        f.write(f"\nd : {hex(d)}")
        f.write(f"\nd_inv_vesta : {hex(d_inv_vesta)}")
        f.write(f"\nrounds (vesta) : {n_vesta}")
        f.write(f"\nMDS (vesta): {[hex(v) for r in mds_vesta for v in r]}")
        f.write(f"\nRC (vesta): {[hex(v) for v in rounds_vesta]}")
        f.write(f"\nd_inv_bls12 : {hex(d_inv_bls12)}")
        f.write(f"\nrounds (bls12) : {n_bls12}")
        f.write(f"\nMDS (bls12): {[hex(v) for r in mds_bls12 for v in r]}")
        f.write(f"\nRC (bls12): {[hex(v) for v in rounds_bls12]}")

    pbar.update()

    ### ----- Griffin ----- ###
    filename = 'griffin.txt'
    n = 12 # based on the paper when t = 3 and d = 5

    alpha_bls12, beta_bls12, consts_bls12 = get_params_griffin(bls12, seeding_bls12, m, n)
    alpha_vesta, beta_vesta, consts_vesta = get_params_griffin(vesta, seeding_vesta, m, n)

    with open(f'config/{filename}', "w") as f:
        f.write(f"\nd : {hex(d)}")
        f.write(f"\nrounds (both) : {n}")
        f.write(f"\nd_inv_vesta : {hex(d_inv_vesta)}") 
        f.write(f"\nalpha (vesta) : {hex(alpha_vesta)}")
        f.write(f"\nbeta (vesta) : {hex(beta_vesta)}")
        f.write(f"\nRC (vesta): {[hex(v) for v in consts_vesta]}")
        f.write(f"\nd_inv_bls12 : {hex(d_inv_bls12)}")
        f.write(f"\nalpha (bls12) : {hex(alpha_bls12)}")
        f.write(f"\nbeta (bls12) : {hex(beta_bls12)}")
        f.write(f"\nRC (bls12): {[hex(v) for v in consts_bls12]}")

    pbar.update()

    ### ----- Neptune ----- ###
    filename = 'neptune.txt'

    rev, riv = get_nb_rounds_neptune(d, vesta, m_neptune, s)
    reb, rib = get_nb_rounds_neptune(d, bls12, m_neptune, s)

    consts_bls12, gamma_bls12, matrix_bls12 = get_round_constants_neptune(bls12, seeding_bls12, m_neptune, reb+rib)
    consts_vesta, gamma_vesta, matrix_vesta = get_round_constants_neptune(vesta, seeding_vesta, m_neptune, rev+riv)

    with open(f'config/{filename}', "w") as f:
        f.write(f"\nd : {hex(d)}")
        f.write(f"\nd_inv_vesta : {hex(d_inv_vesta)}")
        f.write(f"\nrounds (vesta) : {rev+riv} ({rev}ext +  {riv}int)")
        f.write(f"\ngamma (vesta) : {hex(gamma_vesta)}")
        f.write(f"\nRC (vesta): {[hex(v) for v in consts_vesta]}")
        f.write(f"\nMatrix diagonal (vesta): {[hex(v) for v in matrix_vesta]}")
        f.write(f"\nd_inv_bls12 : {hex(d_inv_bls12)}")
        f.write(f"\nrounds (bls12) : {reb+rib} ({reb}ext +  {rib}int)")
        f.write(f"\ngamma (bls12) : {hex(gamma_bls12)}")
        f.write(f"\nRC (bls12): {[hex(v) for v in consts_bls12]}")
        f.write(f"\nMatrix diagonal (bls12): {[hex(v) for v in matrix_bls12]}")

    pbar.update()

    ### ----- Reinforced Concrete ----- ###
    filename = 'concrete.txt'
    n_concrete = 8
    n_bricks = 6
    ab = [1, 3, 2, 4]

    assert(check_ab(ab[0], ab[2], vesta))
    assert(check_ab(ab[1], ab[3], vesta))   
    assert(check_ab(ab[0], ab[2], bls12))
    assert(check_ab(ab[1], ab[3], bls12))

    rounds_bls12 = get_rounds_concrete(bls12, seeding_bls12, m, n_concrete)
    rounds_vesta = get_rounds_concrete(vesta, seeding_vesta, m, n_concrete)

    with open(f'config/{filename}', "w") as f:
        f.write(f"\nd : {hex(d)}")
        f.write(f"\nRC (vesta): {[hex(v) for v in rounds_vesta]}")

    # bars constants in annex file

    pbar.update()
    
    ### ----- Ciminion ----- ###
    filename = 'ciminion.txt'

    consts_bls12 = get_round_constants_ciminion(bls12, 134)
    consts_vesta = get_round_constants_ciminion(vesta, 134)

    with open(f'config/{filename}', "w") as f:
        f.write(f"\nd : {hex(d)}")
        f.write(f"\nd_inv_vesta : {hex(d_inv_vesta)}")
        f.write(f"\nRC (vesta): {[hex(v) for v in consts_vesta]}")
        f.write(f"\nd_inv_bls12 : {hex(d_inv_bls12)}")
        f.write(f"\nRC (bls12): {[hex(v) for v in consts_bls12]}")

    pbar.update()

