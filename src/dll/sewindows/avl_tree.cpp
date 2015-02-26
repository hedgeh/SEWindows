#include "stdafx.h"
#include "avl_tree.h"


VOID avl_tree_init(
    _Out_ pst_avl_tree Tree,
    _In_ func_avl_tree_compare CompareFunction
    )
{
    Tree->Root.Parent = NULL;
    Tree->Root.Left = NULL;
    Tree->Root.Right = NULL;
    Tree->Root.Balance = 0;
    Tree->Count = 0;

    Tree->CompareFunction = CompareFunction;
}


FORCEINLINE pst_avl_nodes avl_tree_find_element(
    _In_ pst_avl_tree Tree,
    _In_ pst_avl_nodes Element,
    _Out_ PLONG Result
    )
{
    pst_avl_nodes links;
    LONG result;

    links = ROOT_ELEMENT_OF_TREE(Tree);

    if (!links)
    {
        *Result = 1;

        return &Tree->Root;
    }

    while (TRUE)
    {
        result = Tree->CompareFunction(Element, links);

        if (result == 0)
        {
            *Result = 0;

            return links;
        }
        else if (result < 0)
        {
            if (links->Left)
            {
                links = links->Left;
            }
            else
            {
                *Result = -1;

                return links;
            }
        }
        else
        {
            if (links->Right)
            {
                links = links->Right;
            }
            else
            {
                *Result = 1;

                return links;
            }
        }
    }
}

FORCEINLINE VOID avl_tree_left_rotate(
    _Inout_ pst_avl_nodes *Root
    )
{
    pst_avl_nodes P;
    pst_avl_nodes Q;

    //    P
    //  |   |
    //  A   Q
    //     | |
    //     B C
    //
    // becomes
    //
    //    Q
    //  |   |
    //  P   C
    // | |
    // A B
    //


    P = *Root;
    Q = P->Right;
    *Root = Q;
    Q->Parent = P->Parent;
    P->Right = Q->Left;

    if (P->Right)
        P->Right->Parent = P;

    Q->Left = P;
    P->Parent = Q;
}

FORCEINLINE VOID avl_tree_left_twice_rotate(
    _Inout_ pst_avl_nodes *Root
    )
{
    pst_avl_nodes P;
    pst_avl_nodes Q;
    pst_avl_nodes R;

    //     P
    //  |     |
    //  A     Q
    //      |   |
    //      R   D
    //     | |
    //     B C
    //
    // becomes
    //
    //     R
    //  |     |
    //  P     Q
    // | |   | |
    // A B   C D


    P = *Root;
    Q = P->Right;
    R = Q->Left;



    *Root = R;
    R->Parent = P->Parent;



    Q->Left = R->Right;

    if (Q->Left)
        Q->Left->Parent = Q;


    R->Right = Q;
    Q->Parent = R;


    P->Right = R->Left;

    if (P->Right)
        P->Right->Parent = P;


    R->Left = P;
    P->Parent = R;
}

FORCEINLINE VOID avl_tree_right_rotate(
    _Inout_ pst_avl_nodes *Root
    )
{
    pst_avl_nodes Q;
    pst_avl_nodes P;

    //    Q
    //  |   |
    //  P   C
    // | |
    // A B
    //
    // becomes
    //
    //    P
    //  |   |
    //  A   Q
    //     | |
    //     B C
    //


    Q = *Root;
    P = Q->Left;



    *Root = P;
    P->Parent = Q->Parent;



    Q->Left = P->Right;

    if (Q->Left)
        Q->Left->Parent = Q;


    P->Right = Q;
    Q->Parent = P;
}

FORCEINLINE VOID avl_tree_right_twice_rotate(
    _Inout_ pst_avl_nodes *Root
    )
{
    pst_avl_nodes P;
    pst_avl_nodes Q;
    pst_avl_nodes R;

    //       P
    //    |     |
    //    Q     D
    //  |   |
    //  A   R
    //     | |
    //     B C
    //
    // becomes
    //
    //     R
    //  |     |
    //  Q     P
    // | |   | |
    // A B   C D
    //


    P = *Root;
    Q = P->Left;
    R = Q->Right;



    *Root = R;
    R->Parent = P->Parent;


    Q->Right = R->Left;

    if (Q->Right)
        Q->Right->Parent = Q;


    R->Left = Q;
    Q->Parent = R;


    P->Left = R->Right;

    if (P->Left)
        P->Left->Parent = P;


    R->Right = P;
    P->Parent = R;
}

ULONG avl_tree_rebalance(
    _Inout_ pst_avl_nodes *Root
    )
{
    pst_avl_nodes P;
    pst_avl_nodes Q;
    pst_avl_nodes R;

    P = *Root;

    if (P->Balance == -1)
    {
        Q = P->Left;

        if (Q->Balance == -1)
        {
            // Left-left

            avl_tree_right_rotate(Root);

            P->Balance = 0;
            Q->Balance = 0;

            return 1;
        }
        else if (Q->Balance == 1)
        {
            // Left-right

            R = Q->Right;

            avl_tree_right_twice_rotate(Root);

            if (R->Balance == -1)
            {
                P->Balance = 1;
                Q->Balance = 0;
            }
            else if (R->Balance == 1)
            {
                P->Balance = 0;
                Q->Balance = -1;
            }
            else
            {
                P->Balance = 0;
                Q->Balance = 0;
            }

            R->Balance = 0;

            return 2;
        }
        else
        {
            //    D
            //  |   |
            //  B   E
            // | |
            // A C
            //
            // Removing E
            //
            //    D
            //  |
            //  B
            // | |
            // A C
            //
      
            //
            //   B
            // |   |
            // A   D
            //    |
            //    C
            //

            avl_tree_right_rotate(Root);

            Q->Balance = 1;

            return 3;
        }
    }
    else
    {
        Q = P->Right;

        if (Q->Balance == 1)
        {
            // Right-right

            avl_tree_left_rotate(Root);

            P->Balance = 0;
            Q->Balance = 0;

            return 1;
        }
        else if (Q->Balance == -1)
        {
            // Right-left

            R = Q->Left;

            avl_tree_left_twice_rotate(Root);

            if (R->Balance == -1)
            {
                P->Balance = 0;
                Q->Balance = 1;
            }
            else if (R->Balance == 1)
            {
                P->Balance = -1;
                Q->Balance = 0;
            }
            else
            {
                P->Balance = 0;
                Q->Balance = 0;
            }

            R->Balance = 0;

            return 2;
        }
        else
        {
            avl_tree_left_rotate(Root);

            Q->Balance = -1;

            return 3;
        }
    }
}


pst_avl_nodes avl_tree_add_node(
    _Inout_ pst_avl_tree Tree,
    _Out_ pst_avl_nodes Element
    )
{
    LONG			result;
    pst_avl_nodes	P;
    pst_avl_nodes	root;
    LONG balance;

    P = avl_tree_find_element(Tree, Element, &result);

    if (result < 0)
        P->Left = Element;
    else if (result > 0)
        P->Right = Element;
    else
        return P;

    Element->Parent = P;
    Element->Left = NULL;
    Element->Right = NULL;
    Element->Balance = 0;

    // Balance the tree.

    P = Element;
    root = ROOT_ELEMENT_OF_TREE(Tree);

    while (P != root)
    {
        // In this implementation, the balance factor is the right height minus left height.

        if (P->Parent->Left == P)
            balance = -1;
        else
            balance = 1;

        P = P->Parent;

        if (P->Balance == 0)
        {
            // The balance becomes -1 or 1. Rotations are not needed
            // yet, but we should keep tracing upwards.

            P->Balance = balance;
        }
        else if (P->Balance != balance)
        {
            // The balance is opposite the new balance, so it now
            // becomes 0.

            P->Balance = 0;

            break;
        }
        else
        {
            pst_avl_nodes *ref;

            // The balance is the same as the new balance, meaning
            // it now becomes -2 or 2. Rotations are needed.

            if (P->Parent->Left == P)
                ref = &P->Parent->Left;
            else
                ref = &P->Parent->Right;

            avl_tree_rebalance(ref);

            break;
        }
    }

    Tree->Count++;

    return NULL;
}

VOID avl_tree_remove_node(
    _Inout_ pst_avl_tree Tree,
    _Inout_ pst_avl_nodes Element
    )
{
    pst_avl_nodes newElement;
    pst_avl_nodes *replace;
    pst_avl_nodes P;
    pst_avl_nodes root;
    LONG balance;

    if (!Element->Left || !Element->Right)
    {
        newElement = Element;
    }
    else if (Element->Balance >= 0) // pick the side depending on the balance to minimize rebalances
    {
        newElement = Element->Right;

        while (newElement->Left)
            newElement = newElement->Left;
    }
    else
    {
        newElement = Element->Left;

        while (newElement->Right)
            newElement = newElement->Right;
    }

    if (newElement->Parent->Left == newElement)
    {
        replace = &newElement->Parent->Left;
        balance = -1;
    }
    else
    {
        replace = &newElement->Parent->Right;
        balance = 1;
    }

    if (!newElement->Right)
    {
        *replace = newElement->Left;

        if (newElement->Left)
            newElement->Left->Parent = newElement->Parent;
    }
    else
    {
        *replace = newElement->Right;
        newElement->Right->Parent = newElement->Parent; // we know Right exists
    }

    P = newElement->Parent;
    root = &Tree->Root;

    while (P != root)
    {
        if (P->Balance == balance)
        {
            // The balance is cancelled by the remove operation and becomes 0.
            // Rotations are not needed yet, but we should keep tracing upwards.

            P->Balance = 0;
        }
        else if (P->Balance == 0)
        {
            // The balance is 0, so it now becomes -1 or 1.

            P->Balance = -balance;

            break;
        }
        else
        {
            pst_avl_nodes *ref;

            // The balance is the same as the new balance, meaning
            // it now becomes -2 or 2. Rotations are needed.

            if (P->Parent->Left == P)
                ref = &P->Parent->Left;
            else
                ref = &P->Parent->Right;

            // We can stop tracing if we have a special case rotation.
            if (avl_tree_rebalance(ref) == 3)
                break;

            P = P->Parent;
        }

        if (P->Parent->Left == P)
            balance = -1;
        else
            balance = 1;

        P = P->Parent;
    }

    if (newElement != Element)
    {
        // Replace the subject with the new subject.

        *newElement = *Element;

        if (Element->Parent->Left == Element)
            newElement->Parent->Left = newElement;
        else
            newElement->Parent->Right = newElement;

        if (newElement->Left)
            newElement->Left->Parent = newElement;
        if (newElement->Right)
            newElement->Right->Parent = newElement;
    }

    Tree->Count--;
}


pst_avl_nodes avl_tree_find_node(
    _In_ pst_avl_tree Tree,
    _In_ pst_avl_nodes Element
    )
{
    pst_avl_nodes links;
    LONG result;

    links = avl_tree_find_element(Tree, Element, &result);

    if (result == 0)
        return links;
    else
        return NULL;
}


pst_avl_nodes avl_tree_find_closest_node(
    _In_ pst_avl_tree Tree,
    _In_ pst_avl_nodes Element,
    _Out_ PLONG Result
    )
{
    pst_avl_nodes links;
    LONG result;

    links = avl_tree_find_element(Tree, Element, &result);

    if (links == &Tree->Root)
        return NULL;

    *Result = result;

    return links;
}


pst_avl_nodes avl_tree_minimum_node(
    _In_ pst_avl_tree Tree
    )
{
    pst_avl_nodes links;

    links = ROOT_ELEMENT_OF_TREE(Tree);

    if (!links)
        return NULL;

    while (links->Left)
        links = links->Left;

    return links;
}


pst_avl_nodes avl_tree_maximum_node(
    _In_ pst_avl_tree Tree
    )
{
    pst_avl_nodes links;

    links = ROOT_ELEMENT_OF_TREE(Tree);

    if (!links)
        return NULL;

    while (links->Right)
        links = links->Right;

    return links;
}


pst_avl_nodes avl_tree_successor_node(
    _In_ pst_avl_nodes Element
    )
{
    pst_avl_nodes links;

    if (Element->Right)
    {
        Element = Element->Right;

        while (Element->Left)
            Element = Element->Left;

        return Element;
    }
    else
    {
        // Trace back to the next vertical level. Note
        // that this code does in fact return NULL when there
        // are no more elements because of the way the root
        // element is constructed.

        links = Element->Parent;

        while (links && links->Right == Element)
        {
            Element = links;
            links = links->Parent;
        }

        return links;
    }
}


pst_avl_nodes avl_tree_predecessor_node(
    _In_ pst_avl_nodes Element
    )
{
    pst_avl_nodes links;

    if (Element->Left)
    {
        Element = Element->Left;

        while (Element->Right)
            Element = Element->Right;

        return Element;
    }
    else
    {
        links = Element->Parent;

        while (links && links->Left == Element)
        {
            Element = links;
            links = links->Parent;
        }

        if (links)
        {
            // We need an additional check because the tree root is
            // stored in Root.Right, not Left.
            if (!links->Parent)
                return NULL; // reached Root, so no more elements
        }

        return links;
    }
}


VOID avl_tree_enum(
    _In_ pst_avl_tree Tree,
    _In_ tree_enum_order Order,
    _In_ func_avl_tree_enum_callback Callback,
    _In_opt_ PVOID Context
    )
{
    pst_avl_nodes stackBase[47];
    pst_avl_nodes *stack;
    pst_avl_nodes links;

    stack = stackBase;

    switch (Order)
    {
    case tree_enum_order_in_order:
        links = ROOT_ELEMENT_OF_TREE(Tree);

        while (links)
        {
            *stack++ = links;
            links = links->Left;
        }

        while (stack != stackBase)
        {
            links = *--stack;

            if (!Callback(Tree, links, Context))
                break;

            links = links->Right;

            while (links)
            {
                *stack++ = links;
                links = links->Left;
            }
        }

        break;
    case tree_enum_order_reverse_order:
        links = ROOT_ELEMENT_OF_TREE(Tree);

        while (links)
        {
            *stack++ = links;
            links = links->Right;
        }

        while (stack != stackBase)
        {
            links = *--stack;

            if (!Callback(Tree, links, Context))
                break;

            links = links->Left;

            while (links)
            {
                *stack++ = links;
                links = links->Right;
            }
        }

        break;
    }
}
