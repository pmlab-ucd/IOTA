import string

from nltk.tree import Tree
from nltk.util import breadth_first
from nltk.parse import CoreNLPParser
from nltk.chunk.regexp import RegexpParser
from nltk.tokenize import sent_tokenize

from lib.constants import device_type_list, device_action_list
from gensim.models import KeyedVectors


def parse_sentence(sentence):
    """
    This function first parses one sentence into clauses. Then it chunks each clause, extracting NP and VP.
    :param sentence: a string of one sentence
    :return: a list of two clauses, where each clause is a list of NP and VP

    >>> (conditional_clause, main_clause) = extract_clauses("Notify me and turn on the light, when the humidity rises above the given threshold, or there is no one at home.")
    >>> print(conditional_clause)
    the humidity rises above the given threshold, or there is no one at home
    >>> print(main_clause)
    Notify me and turn on the light, .
    >>> (cond_relation, cond_split) = split_conditional_clause(conditional_clause)
    >>> print((cond_relation, cond_split))
    ('or', ['the humidity rises above the given threshold', 'there is no one at home'])
    >>> print((main_relation, main_split))
    ('and', ['Notify me', 'turn on the light'])
    >>> print((cond_relation, cond_res, main_relation, main_res))
    ('or', [(['the humidity', 'threshold'], ['rises above', 'given']), (['no one', 'home'], ['is'])], 'and', [([], ['Notify']), (['the light'], ['turn on'])])
    """
    # extract the conditional clause and the main_clause
    (conditional_clause, main_clause) = extract_clauses(sentence)

    # split clauses into simple sentences
    (cond_relation, cond_split) = split_conditional_clause(conditional_clause)
    (main_relation, main_split) = split_main_clause(main_clause)

    # chunk each simple sentence using regex chunker
    # chunk conditional simple sentences
    cond_res = []
    for simp_sen in cond_split:
        cond_res.append(regex_chunk(simp_sen))

    main_res = []
    for simp_sen in main_split:
        main_res.append(regex_chunk(simp_sen))

    return cond_relation, cond_res, main_relation, main_res


def extract_clauses(sentence):
    """
    This function extracts the conditional clause and the main clause from a given sentence.
    :param sentence: a string of one sentence
    :return: a list of strings representing clauses
    """

    # create a CoreNLPParser object
    parser = CoreNLPParser(url='http://localhost:9000')
    # raw_parse the sentence
    temp, = parser.raw_parse(sentence)

    # split the description into conditional clause and main clause
    # do DFS to find SBAR
    conditional_clause = None
    conditional_clause_complete = None
    for subtree in temp.subtrees():
        if subtree.label() == 'SBAR':  # the clause after SBAR is the conditional clause
            conditional_clause_complete = ' '.join(_join_punctuation(subtree.leaves()))
        if conditional_clause_complete and subtree.label() == 'S':
            conditional_clause = ' '.join(_join_punctuation(subtree.leaves()))
            break

    # clean the string by adding spaces between punctuation
    main_clause = sentence.replace(conditional_clause_complete, '')

    return conditional_clause, main_clause


def _join_punctuation(seq, characters='.,;?!'):
    characters = set(characters)
    seq = iter(seq)
    current = next(seq)

    for nxt in seq:
        if nxt in characters:
            current += nxt
        else:
            yield current
            current = nxt

    yield current


def split_conditional_clause(clause):
    """
    This function splits the conditional clause into several simple sentences by coordinating conjunction (CC).
    :param clause: the conditional clause string
    :return: a tuple of something like ('and', [conditionA, conditionB])
    """

    # create a CoreNLPParser object
    parser = CoreNLPParser(url='http://localhost:9000')
    # remove the leading and trailing space and punctuation if there is any
    s = clause.strip()
    s = s[0].translate(str.maketrans('', '', string.punctuation)) + s[1:-1] + s[-1].translate(
        str.maketrans('', '', string.punctuation))
    # raw_parse the sentence
    t, = parser.raw_parse(s)

    res = []
    flag_CC = None
    bfs2 = breadth_first(t)
    first_simple = None
    while True:
        node = next(bfs2)
        if type(node) == str:
            break
        if node.label() == 'S':  # for conditional clause, the two simple sentences are S's
            first_simple = node
        if node.label() == 'CC':
            flag_CC = node.leaves()[0]
            res.append(' '.join(first_simple.leaves()))
            break
    if flag_CC:
        res.append(' '.join(next(bfs2).leaves()))
        if flag_CC == 'and':
            return 'AND', res
        elif flag_CC == 'or':
            return 'OR', res
    elif first_simple:
        return 'NONE', [' '.join(first_simple.leaves())]


def split_main_clause(clause):
    """
    This function splits the main clause into several simple sentences by coordinating conjunction (CC).
    :param clause: the conditional clause string
    :return: a tuple of something like ('and', [doA, doB])
    """

    # create a CoreNLPParser object
    parser = CoreNLPParser(url='http://localhost:9000')
    # remove the leading and trailing space and punctuation if there is any
    s = clause.strip()
    s = s[0].translate(str.maketrans('', '', string.punctuation)) + s[1:-1] + s[-1].translate(
        str.maketrans('', '', string.punctuation))
    # raw_parse the sentence
    t, = parser.raw_parse(s)

    res = []
    flag_CC = None
    bfs2 = breadth_first(t)
    first_simple = None
    while True:
        node = next(bfs2)
        if type(node) == str:
            break
        if node.label() == 'VP':  # for conditional clause, the two simple sentences are S's
            first_simple = node
        if node.label() == 'CC':
            flag_CC = node.leaves()[0]
            res.append(' '.join(first_simple.leaves()))
            break
    if flag_CC:
        res.append(' '.join(next(bfs2).leaves()))
        if flag_CC == 'and':
            return 'AND', res
        elif flag_CC == 'or':
            return 'OR', res
    elif first_simple:
        return 'NONE', [' '.join(first_simple.leaves())]


def regex_chunk(simple_sentence):
    """
    This function extracts the noun phrase and verb phrase from a given clause.
    :param simple_sentence: a string of a simple sentence
    :return: a tuple of NP list and VP list

    >>> print(regex_chunk('turn on the light'))
    (['the light'], ['turn on'])
    """

    # Extract noun phrase and verb phrase for each sub-sentence using chunking
    grammar = """
        NP: {<DT>?<JJ>*<NN.*>+} # Chunk sequences of DT, JJ, NN
        VP: {<VB.*><IN|RP>?} # Chunk verbs and their arguments
        """
    chunk_parser = RegexpParser(grammar)

    parser = CoreNLPParser(url='http://localhost:9000')
    t, = parser.raw_parse(simple_sentence)

    leaves = [] # this is the tagging for each word which is more accurate
    for subtree in t.subtrees():
        if type(subtree[0]) != Tree:  # the clause after SBAR is the conditional clause
            leaves.append((subtree[0], subtree.label()))

    noun_phrases = [' '.join(leaf[0] for leaf in tree.leaves()) for tree in chunk_parser.parse(leaves).subtrees() if tree.label()=='NP']
    verb_phrases = [' '.join(leaf[0] for leaf in tree.leaves()) for tree in chunk_parser.parse(leaves).subtrees() if tree.label()=='VP']

    return noun_phrases, verb_phrases


def match_word(model, clause_res, device_type_list, device_action_list):
    """
    For a clause, match each noun phrase and verb phrase to the device name and device action.
    :param model: the trained word2vec model
    :param clause_res: conditional clause or the main clause
    :param device_type_list: a list of device types
    :param device_action_list: a list of device actions
    :return: for each noun phrase / verb phrase, return the corresponding device type and device action

    >>> clause_res = [(['the humidity', 'threshold'], ['rises above', 'given']), (['no one', 'home'], ['is'])]
    >>> print(clause_res[0])
    (['the humidity', 'threshold'], ['rises above', 'given'])
    >>> (np_list, vp_list) = clause_res[0]
    >>> print(np_list)
    ['the humidity', 'threshold']
    >>> print(vp_list)
    ['rises above', 'given']
    """

    np_res = []
    vp_res = []
    for (np_list, vp_list) in clause_res:
        # match noun to device type
        dev_match = None
        dev_match_sim = 0
        for np in np_list:
            for noun in np.split():
                for dev in device_type_list:
                    for word in dev.split():
                        try:
                            temp_score = model.similarity(noun, word)
                        except:
                            continue
                        if temp_score > dev_match_sim:
                            dev_match_sim = temp_score
                            dev_match = dev

        # match verb to device action
        act_match = None
        act_match_sim = 0
        for vp in vp_list:
            for verb in vp.split():
                for act in device_action_list:
                    temp_score = model.similarity(verb, act)
                    if temp_score > act_match_sim:
                        act_match_sim = temp_score
                        act_match = act

        np_res.append(dev_match)
        vp_res.append(act_match)

    return np_res, vp_res # (['humidity sensor', 'game console'], ['high', 'on'])


def app_logic_extractor(app_desc):
    """
    Extract the essential logic from an IoT app description and return a structured form

    :param app_desc: a string of an IoT app description in natural language
    :return: a tuple of (cond_relation, cond_np_list, cond_vp_list, main_relation, main_np_list, main_vp_list)
    """
    # Load Google's pre-trained Word2Vec model.
    model = KeyedVectors.load_word2vec_format('PATH_TO_PRE_TRAINED_WORD2VEC_MODEL', binary=True)

    try:
        # split app description into sentence(s)
        desc_list = sent_tokenize(app_desc)

        # if an app description contains more than one sentence, always parse the first sentence
        (cond_relation, cond_res, main_relation, main_res) = parse_sentence(desc_list[0])

        # match word for the conditional clause
        (cond_np_list, cond_vp_list) = match_word(model, cond_res, device_type_list, device_action_list)

        # match word for the main clause
        (main_np_list, main_vp_list) = match_word(model, main_res, device_type_list, device_action_list)

        return cond_relation, cond_np_list, cond_vp_list, main_relation, main_np_list, main_vp_list

    except:
        print('error: parse app description failed\n')
        return None


def test_app_logic_extractor():
    return app_logic_extractor('Turn on the hall light if someone comes home and the door opens.')
    # should return:
    # ('AND', ['toaster', 'door contact sensor'], ['close', 'open'], 'NONE', ['light sensor'], ['on'])


if __name__ == '__main__':
    print(test_app_logic_extractor())
